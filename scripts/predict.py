import joblib
import argparse
import json
import os
import numpy as np
from datetime import datetime

from xweirdfor.extract_features import extract_features
from xweirdfor.heuristics import analyze_headers


def load_model(model_path):
    """
    Load either a single or ensemble model.
    """
    model_data = joblib.load(model_path)

    if isinstance(model_data, dict) and model_data.get("type") == "ensemble":
        return model_data
    else:
        return {"type": "single", "model": model_data}


def predict_single_model(model, features):
    """
    Get prediction from a single model.
    """
    score = model.decision_function([features])[0]
    prediction = model.predict([features])[0]
    verdict = "suspicious" if prediction == -1 else "normal"
    return verdict, score


def predict_ensemble_model(models, features):
    """
    Get prediction from ensemble with detailed voting information.
    For static analysis, provides rich information about the decision.
    """
    votes = []
    scores = []

    for name, model in models:
        score = model.decision_function([features])[0]
        prediction = model.predict([features])[0]
        verdict = "suspicious" if prediction == -1 else "normal"

        votes.append({
            "model": name,
            "verdict": verdict,
            "score": score,
            "confidence": abs(score)
        })
        scores.append(score)

    # Aggregate decisions
    suspicious_votes = sum(1 for v in votes if v["verdict"] == "suspicious")
    total_votes = len(votes)

    # Weighted average score
    avg_score = np.mean(scores)
    median_score = np.median(scores)
    std_score = np.std(scores)

    # Final verdict based on majority vote
    if suspicious_votes > total_votes / 2:
        final_verdict = "suspicious"
    elif suspicious_votes == 0:
        final_verdict = "normal"
    else:
        final_verdict = "gray"

    # Confidence based on agreement
    if suspicious_votes == 0 or suspicious_votes == total_votes:
        confidence = 1.0
    else:
        confidence = abs(suspicious_votes - (total_votes / 2)) / (total_votes / 2)

    return {
        "verdict" : final_verdict,
        "avg_score": avg_score,
        "median_score": median_score,
        "score_std": std_score,
        "confidence": confidence,
        "votes": votes,
        "vote_summary": f"{suspicious_votes}/{total_votes} suspicious"
    }


def run_prediction(model_data, header_dict):
    """
    Run prediction with either single or ensemble data.
    """
    features = extract_features(header_dict)

    if model_data["type"] == "single":
        verdict, score = predict_single_model(model_data["model"], features)
        return {
            "verdict": verdict,
            "score": score,
            "model_type": "single"
        }
    else:
        ensemble_result = predict_ensemble_model(model_data["models"], features)
        ensemble_result["model_type"] = "ensemble"
        return ensemble_result


def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP headers for anomalies.")
    parser.add_argument("--input", required=True, help="Path to header JSON file")
    parser.add_argument("--save-output", help="Save predictions to file (JSON)")
    parser.add_argument("--output-dir", default="results/predictions", help="Directory for saved predictions")
    parser.add_argument("--model", default="models/model.pkl", help="Path to model or ensemble")
    parser.add_argument("--verbose", action="store_true", help="Show detailed voting info")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
 
    args = parser.parse_args()

    # Load headers
    with open(args.input, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        header_sets = data
    else:
        header_sets = [data]

    # Load model
    model_data = load_model(args.model)

    all_results = []

    for i, headers in enumerate(header_sets):
        ml_result = run_prediction(model_data, headers)
        heuristics = analyze_headers(headers)

        result = {
            "index": i,
            **ml_result,
            "heuristic_risk": heuristics.get("risk_score", 0),
            "heuristic_risk_level": heuristics.get("risk_level", "unknown"),
        }

        # Add heuristic details if they exist
        if heuristics.get("missing_critical_headers"):
            result["missing_critical_headers"] = heuristics["missing_critical_headers"]
        if heuristics.get("suspicious_headers"):
            result["suspicious_headers"] = heuristics["suspicious_headers"]

        # Calculate combined verdict (for ensemble, this is more nuanced)
        if model_data["type"] == "ensemble":
            if ml_result["verdict"] == "gray":
                # Use heuristics as a tiebreaker
                if heuristics.get("risk_score", 0) > 0.5:
                    result["final_verdict"] = "suspicious"
                elif heuristics.get("risk_score", 0) < 0.2:
                    result["final_verdict"] = "normal"
                else:
                    result["final_verdict"] = "gray"
            else:
                result["final_verdict"] = ml_result["verdict"]
        else:
            # Single model: simple combination
            if ml_result["verdict"] == "suspicious" or heuristics.get("risk_score", 0) > 0.7:
                result["final_verdict"] = "suspicious"
            else:
                result["final_verdict"] = ml_result["verdict"]

        # Collect results if saving
        if args.save_output:
            all_results.append(result)

        # Output
        if args.format == "json":
            if not args.verbose and "votes" in result:
                # Remove detailed voting info unless verbose
                result.pop("votes", None)
            print(json.dumps(result, indent=2))
        else:
            # Text format
            print(f"\n{'='*60}")
            print(f"Sample {i}: {result['final_verdict'].upper()}")
            print(f"Model type: {result['model_type']}")

            if result["model_type"] == "ensemble":
                print(f"ML Votes: {result['vote_summary']}")
                print(f"Confidence: {result['confidence']:.1%}")
                if args.verbose:
                    print("\nDetailed Votes:")
                    for vote in result.get("votes", []):
                        print(f"  {vote['model']:12} -> {vote['verdict']:10} (score: {vote['score']:.3f})")
            else:
                print(f"ML Score: {result['score']:.3f}")

            print(f"Heuristic Risk: {result['heuristic_risk']:.1%} ({result['heuristic_risk_level']})")

            if result.get("missing_critical_headers"):
                print(f"\nMissing Critical Headers: {', '.join(result['missing_critical_headers'])}")

            if result.get("suspicious_headers"):
                print(f"Suspicious Headers: {len(result['suspicious_headers'])} found")

    # Save results if requested
    if args.save_output:
        os.makedirs(args.output_dir, exist_ok=True)

        # Generate a filename with timestamp if not specified
        if args.save_output == "auto":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"predictions_{timestamp}.json"
        else:
            filename = args.save_output
        
        output_path = os.path.join(args.output_dir, filename)

        # Add metadata
        output_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "model_path": args.model,
                "input_file": args.input,
                "total_samples": len(all_results),
                "summary": {
                    "normal": sum(1 for r in all_results if r["final_verdict"] == "normal"),
                    "suspicious": sum(1 for r in all_results if r["final_verdict"] == "suspicious"),
                    "gray": sum(1 for r in all_results if r["final_verdict"] == "gray")
                }
            },
            "predictions": all_results
        }

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\n{'='*60}")
        print(f"Predictions saved to: {output_path}")
        print(f"Summary: {output_data['metadata']['summary']}")



if __name__ == "__main__":
    main()