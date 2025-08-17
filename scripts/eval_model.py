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

def create_comprehensive_plots(y_true, y_scores, y_pred, output_dir="results/evaluation"):
    """
    Create evaluation plots.
    """
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))

    # 1. Score distribution
    ax = axes[0, 0]
    normal_scores = [s for s, l in zip(y_scores, y_true) if l == "normal"]
    suspicious_scores = [s for s, l in zip(y_scores, y_true) if l == "suspicious"]

    ax.hist(normal_scores, bins=30, alpha=0.5, label="Normal", color="green", density=True)
    ax.hist(suspicious_scores, bins=30, alpha=0.5, lable="Suspicious", color="red", density=True)
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
    plt.savefig(f"{output_dir}/score_distribution.png", dpi=150)
    print(f"Comprehensive evaluation plots saved to {output_dir}/score_distribution.png")

    return best_threshold