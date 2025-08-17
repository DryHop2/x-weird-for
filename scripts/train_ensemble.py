import argparse
import json
import joblib
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from sklearn.ensemble import IsolationForest
from xweirdfor.extract_features import extract_features



def train_ensemble(features, base_contamination=0.1):
    """
    Train multiple models with different parameters.
    This provides different 'perspectives' on anomalies.
    """
    models = []

    # Model 1: Conservative (fewer anomalies)
    model1 = IsolationForest(
        n_estimators=100,
        contamination=base_contamination * 0.5,
        max_features=1.0,
        random_state=42
    )
    model1.fit(features)
    models.append(("conservative", model1))

    # Model 2: Balanced (standard)
    model2 = IsolationForest(
        n_estimators=150,
        contamination=base_contamination,
        max_features=0.8,
        random_state=43
    )
    model2.fit(features)
    models.append(("balanced", model2))

    # Model 3: Aggressive (more anomalies)
    model3 = IsolationForest(
        n_estimators=200,
        contamination=base_contamination * 1.5,
        max_features=0.6,
        random_state=44
    )
    model3.fit(features)
    models.append(("aggressive", model3))

    # Model 4: Different tree structure
    model4 = IsolationForest(
        n_estimators=100,
        contamination=base_contamination,
        max_features=1.0,
        max_samples=0.8,
        random_state=45
    )
    model4.fit(features)
    models.append(("subsampled", model4))

    return models


def main():
    parser = argparse.ArgumentParser(description="Train ensemble of Isolation Forest models")
    parser.add_argument("--input", required=True, help="Path to training data")
    parser.add_argument("--output", default="models/ensemble.pkl", help="Output file")
    parser.add_argument("--contamination", type=float, default=0.1, help="Base contamination rate")

    args = parser.parse_args()

    # Load data
    with open(args.input, "r") as f:
        data = json.load(f)

    if isinstance(data, list) and len(data) > 0 and "headers" in data[0]:
        header_sets = [d["headers"] for d in data]
    else:
        header_sets = data if isinstance(data, list) else [data]

    # Extract features
    print(f"Extracting features from {len(header_sets)} samples...")
    features = [extract_features(headers) for headers in header_sets]

    # Train ensemble
    print("Training ensemble models...")
    models = train_ensemble(features, args.contamination)

    # Save ensemble
    ensemble_data = {
        "type": "ensemble",
        "models": models,
        "contamination": args.contamination
    }

    joblib.dump(ensemble_data, args.output)
    print(f"Ensemble saved to {args.output}")

    # Print model summaries
    for name, model in models:
        scores = model.decision_function(features)
        anomalies = sum(model.predict(features) == -1)
        print(f"\n{name.upper()} model:")
        print(f"  Anomalies detected: {anomalies}/{len(features)} ({100 * anomalies / len(features):.1f}%)")
        print(f"  Score range: [{scores.min():.3f}, {scores.max():.3f}]")
        print(f"  Mean score: {scores.mean():.3f}")


if __name__ == "__main__":
    main()