import argparse
import json
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    f1_score
)

from xweirdfor.extract_features import extract_features


def load_eval_data(path):
    """
    Load labeled evaluation data.
    """
    with open(path, "r") as f:
        data = json.load(f)
    return data


def predict_verdict(score, threshold=0):
    """
    Convert score to verdict based on threshold.
    """
    return "normal" if score >= threshold else "suspicious"


def create_comprehensive_plots(y_true, y_scores, y_pred, output_dir="results/evaluation"):
    """
    Create evaluation plots.
    """
    os.makedirs(output_dir, exist_ok=True)

    fig, axes = plt.subplots(2, 3, figsize=(15, 10))

    # 1. Score distribution
    ax = axes[0, 0]
    normal_scores = [s for s, l in zip(y_scores, y_true) if l == "normal"]
    suspicious_scores = [s for s, l in zip(y_scores, y_true) if l == "suspicious"]

    ax.hist(normal_scores, bins=30, alpha=0.5, label="Normal", color="green", density=True)
    ax.hist(suspicious_scores, bins=30, alpha=0.5, label="Suspicious", color="red", density=True)
    ax.axvline(x=0, color="black", linestyle="--", label="Default threshold")
    ax.set_title("Anomaly Score Distribution")
    ax.set_xlabel("Score")
    ax.set_ylabel("Density")
    ax.legend()

    # 2. Confusion Matrix
    ax = axes[0, 1]
    cm = confusion_matrix(y_true, y_pred, labels=["normal", "suspicious"])
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                xticklabels=["Normal", "Suspicious"],
                yticklabels=["Normal", "Suspicious"])
    ax.set_title("Confusion Matrix")
    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")

    # 3. ROC Curve
    ax = axes[0, 2]
    # Convert labels to binary
    y_true_binary = [1 if l == "suspicious" else 0 for l in y_true]
    # Invert scores
    y_scores_roc = [-s for s in y_scores]

    fpr, tpr, _ = roc_curve(y_true_binary, y_scores_roc)
    roc_auc = auc(fpr, tpr)

    ax.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {roc_auc:.2f})")
    ax.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend(loc="lower right")

    # 4. Precision-Recall Curve
    ax = axes[1, 0]
    precision, recall, _ = precision_recall_curve(y_true_binary, y_scores_roc)

    ax.plot(recall, precision, color="purple", lw=2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])

    # 5. Score vs Index
    ax = axes[1, 1]
    colors = ["green" if l == "normal" else "red" for l in y_true]
    ax.scatter(range(len(y_scores)), y_scores, c=colors, alpha=0.5, s=10)
    ax.axhline(y=0, color="black", linestyle="--", alpha=0.5)
    ax.set_xlabel("Sample Index")
    ax.set_ylabel("Anomaly Score")
    ax.set_title("Scores by Sample")

    # 6. F1 Score vs Threshold
    ax = axes[1, 2]
    thresholds = np.linspace(min(y_scores), max(y_scores), 50)
    f1_scores = []

    for thresh in thresholds:
        y_pred_thresh = ["normal" if s >= thresh else "suspicious" for s in y_scores]
        f1 = f1_score(y_true, y_pred_thresh, pos_label="suspicious", average="binary")
        f1_scores.append(f1)

    ax.plot(thresholds, f1_scores, color="blue", lw=2)
    best_threshold = thresholds[np.argmax(f1_scores)]
    ax.axvline(x=best_threshold, color="red", linestyle="--", label=f"Best threshold: {best_threshold:.3f}")
    ax.set_xlabel("Threshold")
    ax.set_ylabel("F1 Score")
    ax.set_title("F1 Score vs Threshold")
    ax.legend()

    plt.tight_layout()

    output_file = os.path.join(output_dir, "comprehensive_evaluation.png")
    plt.savefig(output_file, dpi=150)
    print(f"Comprehensive evaluation plots saved to {output_file}")

    return best_threshold


def main():
    parser = argparse.ArgumentParser(description="Evaluate model on labeled data")
    parser.add_argument("--model", default="models/model.pkl", help="Path to trained model")
    parser.add_argument("--input", required=True, help="Path to labeled eval data")
    parser.add_argument("--threshold", type=float, default=0.0, help="Score threshold for normal/suspicious")
    parser.add_argument("--output-dir", default="results/evaluation", help="Directory for output files")
    args = parser.parse_args()

    # Load model and data
    model = joblib.load(args.model)
    data = load_eval_data(args.input)

    # Collect predictions
    y_true = []
    y_pred = []
    all_scores = []

    print("Evaluating model...")
    for entry in data:
        headers = entry["headers"]
        label = entry["label"]

        features = extract_features(headers)
        score = model.decision_function([features])[0]
        verdict = predict_verdict(score, threshold=args.threshold)

        y_true.append(label)
        y_pred.append(verdict)
        all_scores.append(score)

    # Print classification report
    print("\n=== Classification Report ===")
    print(classification_report(y_true, y_pred))

    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_true, y_pred, labels=["normal", "suspicious"]))

    # Calculate average scores
    avg_normal = sum(score for score, label in zip(all_scores, y_true) if label == "normal") / y_true.count("normal")
    avg_suspicious = sum(score for score, label in zip(all_scores, y_true) if label == "suspicious") / y_true.count("suspicious")

    print(f"\nAverage score for normal: {avg_normal:.4f}")
    print(f"Average score for suspicious: {avg_suspicious:.4f}")

    # Create plots and get best threshold
    best_threshold = create_comprehensive_plots(y_true, all_scores, y_pred, args.output_dir)

    print(f"\n=== Optimal Threshold ===")
    print(f"Best threshold for F1 score: {best_threshold:.4f}")

    # Re-evaluate with best threshold
    y_pred_best = [predict_verdict(score, best_threshold) for score in all_scores]
    f1_best = f1_score(y_true, y_pred_best, pos_label="suspicious", average="binary")
    print(f"F1 score with the best threshold: {f1_best:.3f}")


if __name__ == "__main__":
    main()