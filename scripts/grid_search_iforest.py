import argparse
import json
import joblib
from itertools import product
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import IsolationForest

from xweirdfor.extract_features import extract_features


def load_eval_data(path):
    with open(path, "r") as f:
        return json.load(f)
    

def evaluate_model(model, data, threshold):
    y_true = []
    y_pred = []

    for entry in data:
        features = extract_features(entry["headers"])
        score = model.decision_function([features])[0]
        verdict = "normal" if score >= threshold else "suspicious"
        y_true.append(entry["label"])
        y_pred.append(verdict)

    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    f1_suspicious = report["suspicious"]["f1-score"]
    recall_suspicious = report["suspicious"]["recall"]
    accuracy = accuracy_score(y_true, y_pred)

    return f1_suspicious, recall_suspicious, accuracy


def main():
    parser = argparse.ArgumentParser(description="Grid search Isolation Forest hyperparams")
    parser.add_argument("--input", required=True, help="Path to eval_labeled.json")
    parser.add_argument("--threshold", type=float, default=0.0, help="Score threshold for normal/suspicious")
    parser.add_argument("--save-best", action="store_true", help="Save best models as models/best_model.pkl")
    args = parser.parse_args()

    data = load_eval_data(args.input)

    n_estimators_options = [50, 100, 150]
    contamination_options = [0.05, 0.1, 0.15]
    max_features_options = [0.5, 0.75, 1.0]

    best_score = 0
    best_recall = 0
    best_accuracy = 0
    best_model = None
    best_params = None

    print("Starting grid search...\n")

    for n, c, m in product(n_estimators_options, contamination_options, max_features_options):
        model = IsolationForest(
            n_estimators=n,
            contamination=c,
            max_features=m,
            random_state=42
        )

        features = [extract_features(d["headers"]) for d in data]
        model.fit(features)
        
        f1, recall, acc = evaluate_model(model, data, threshold=args.threshold)

        print(f"[n_estimators={n:<3} | contamination:{c:<4} | max_features={m:<4}] -> F1 (suspicious): {f1:.3f} | Recall: {recall:.3f} | Accuracy: {acc:.3f}")

        if (
            f1 > best_score or
            (f1 == best_score and recall > best_recall) or
            (f1 == best_score and recall > best_recall and acc > best_accuracy)):
            best_score = f1
            best_recall = recall
            best_accuracy = acc
            best_model = model
            best_params = (n, c, m)

        
    print("\n\nBest config:")
    print(f"n_estimators={best_params[0]}, contamination={best_params[1]}, max_features={best_params[2]}")
    print(f"Best accuracty: {best_score:.3f}")

    if args.save_best and best_model:
        joblib.dump(best_model, "models/best_model.pkl")
        print("Best model saved to models/best_model.pkl")


if __name__ == "__main__":
    main()