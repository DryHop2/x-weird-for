import joblib
import argparse
import json
import sys
from pathlib import Path

from xweirdfor.extract_features import extract_features
from xweirdfor.heuristics import analyze_headers

sys.path.append(str(Path(__file__).resolve().parent.parent))


def load_model(model_path):
    return joblib.load(model_path)


def run_prediction(model, header_dict):
    features = extract_features(header_dict)
    score = model.decision_function([features])[0]
    prediction = model.predict([features])[0]
    verdict = "suspicious" if prediction == -1 else "normal"
    return verdict, score


def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP headers for anomalies.")
    parser.add_argument("--input", required=True, help="Path to header JSON file")
    parser.add_argument("--model", default="models/model.pkl", help="Path to saved model")
    parser.add_argument("--bulk", action="store_true", help="Enable batch mode for multiple header sets")

    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    if args.bulk:
        if not isinstance(data, list):
            raise ValueError("Bulk mode requires a list of header objects.")
        header_sets = data
    else:
        if not isinstance(data, dict):
            raise ValueError("Single mode requires a single header object.")
        header_sets = [data]

    model = load_model(args.model)

    for i, headers in enumerate(header_sets):
        verdict, score = run_prediction(model, headers)
        heuristics = analyze_headers(headers)

        result = {
            "index": i,
            "verdict": verdict,
            "score": score,
            **heuristics
        }

        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()