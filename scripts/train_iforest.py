import argparse
import json
import joblib
from sklearn.ensemble import IsolationForest

from xweirdfor.extract_features import extract_features


def load_data(path):
    with open(path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Training data must be a list of header objects.")
    
    return data


def build_feature_matrix(header_sets):
    return [extract_features(headers) for headers in header_sets]


def train_model(features):
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    model.fit(features)
    return model


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest on HTTP headers")
    parser.add_argument("--input", required=True, help="Path to JSON file of header sets")
    parser.add_argument("--output", default="model.pkl", help="Output model file")

    args = parser.parse_args()
    data = load_data(args.input)
    features = build_feature_matrix(data)
    model = train_model(features)

    joblib.dump(model, args.output)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()