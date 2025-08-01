import argparse
import json
import joblib
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

from xweirdfor.extract_features import extract_features


def load_eval_data(path):
    with open(path, "r") as f:
        data = json.load(f)
    return data


def predict_verdict(score, threshold=0):
    return "normal" if score >= threshold else "suspicious"


def main():
    parser = argparse.ArgumentParser(description="Evaluate model on labeled data")
    parser.add_argument("--model", default="models/model.pkl", help="Path to trained model")
    parser.add_argument("--input", required=True, help="Path to labeled eval data")
    parser.add_argument("--threshold", type=float, default=0.0, help="Score threshold for normal/suspicious")
    args = parser.parse_args()

    model = joblib.load(args.model)
    data = load_eval_data(args.input)

    y_true = []
    y_pred = []
    all_scores =[]

    for entry in data:
        headers = entry["headers"]
        label = entry["label"]

        features = extract_features(headers)
        score = model.decision_function([features])[0]
        verdict = predict_verdict(score, threshold=args.threshold)

        y_true.append(label)
        y_pred.append(verdict)
        all_scores.append(score)

    print("=== Classification Report ===")
    print(classification_report(y_true, y_pred))

    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_true, y_pred, labels=["normal", "suspicious"]))

    avg_normal = sum(score for score, label in zip(all_scores, y_true) if label == "normal") / y_true.count("normal")
    avg_suspicious = sum(score for score, label in zip(all_scores, y_true) if label == "suspicious") / y_true.count("suspicious")
    print(f"Average score for normal:  {avg_normal:.4f}")
    print(f"Average score for suspicious:  {avg_suspicious:.4f}")

    normal_scores = [score for score, label in zip(all_scores, y_true) if label == "normal"]
    suspicious_scores = [score for score, label in zip(all_scores, y_true) if label == "suspicious"]

    bins = np.linspace(-0.1, 0.2, 100)

    plt.hist(normal_scores, bins=bins, alpha=0.5, label="normal", color="green", density=True, histtype="step")
    plt.hist(suspicious_scores, bins=bins, alpha=0.5, label="suspicious", color="red", density=True, histtype="step")
    plt.axvline(x=args.threshold, color="black", linestyle="--", label="threshold")
    plt.title("Isolation Forest Anomaly Scores")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.savefig("examples/score_distribution.png")
    print("Score plot saved to examples/score_distribution.png")


if __name__ == "__main__":
    main()