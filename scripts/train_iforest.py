import argparse
import json
import joblib
import sys
from sklearn.ensemble import IsolationForest
from pathlib import Path

from xweirdfor.extract_features import extract_features

sys.path.append(str(Path(__file__).resolve().parent.parent))


def load_data(path):
    with open(path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Training data must be a list of header objects.")
    
    return data


def build_feature_matrix(header_sets):
    return [extract_features(headers) for headers in header_sets]


def train_model(features, n_estimators, contamination, max_features):
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_features=max_features,
        random_state=42
    )
    model.fit(features)
    return model


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on HTTP headers")
    parser.add_argument("--input", required=True, help="Path to JSON file of header sets")
    parser.add_argument("--output", default="model.pkl", help="Output model file")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees (default: 100)")
    parser.add_argument("--contamination", type=float, default=0.1, help="Expected proportion of anomalies (default: 0.1)")
    parser.add_argument("--max-features", type=float, default=1.0, help="Number of features to draw at each split (default: 1.0)")

    args = parser.parse_args()
    data = load_data(args.input)
    features = build_feature_matrix(data)
    model = train_model(
        features,
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        max_features=args.max_features
    )

    joblib.dump(model, args.output)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()