import argparse
import json
import joblib

from sklearn.ensemble import IsolationForest
from xweirdfor.extract_features import extract_features


def train_model(features, n_estimators, contamination, max_features, max_samples):
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_features=max_features,
        max_samples=max_samples,
        random_state=42
    )
    model.fit(features)
    return model


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on HTTP headers")
    parser.add_argument("--input", required=True, help="Path to training data")
    parser.add_argument("--output", default="models/model.pkl", help="Output file")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of base estimators")
    parser.add_argument("--max-features", type=float, default=1.0, help="Number of features to draw to train base estimator")
    parser.add_argument("--contamination", type=float, default=0.1, help="Base contamination rate")
    parser.add_argument("--max-samples", default="auto", help="Number of samples to draw to train base estimator [int or float]")

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

    # Train model
    print("Training Isolation Forest...")
    model = train_model(
        features, 
        args.n_estimators, 
        args.contamination, 
        args.max_features, 
        args.max_samples
    )

    # Save model
    joblib.dump(model, args.output)
    print(f"Model saved to {args.output}")

    # Print summary
    scores = model.decision_function(features)
    anomalies = sum(model.predict(features) == -1)
    print(f"\nTraining complete:")
    print(f"  Anomalies detected: {anomalies}/{len(features)} ({100 * anomalies/len(features):.1f}%)")
    print(f"  Score range: [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"  Mean score: {scores.mean():.3f}")


if __name__ == "__main__":
    main()