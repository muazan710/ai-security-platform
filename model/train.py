"""
Train & compare Logistic Regression, Random Forest, and XGBoost
on the phishing URL dataset. Saves the best model + metrics + plots.
"""
import sys, os, json
sys.path.append(os.path.dirname(__file__))

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, confusion_matrix, classification_report)
from xgboost import XGBClassifier

from features import extract_feature_vector, FEATURE_COLUMNS

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "dataset", "phishing_dataset.csv")
MODEL_DIR = os.path.dirname(__file__)


def build_feature_table(df):
    rows = [extract_feature_vector(u) for u in df["url"]]
    X = pd.DataFrame(rows)[FEATURE_COLUMNS]
    return X


def main():
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded dataset: {len(df)} rows")
    print(df["label"].value_counts())

    # --- Data cleaning ---
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset="url")

    X = build_feature_table(df)
    le = LabelEncoder()
    y = le.fit_transform(df["label"])  # malicious/safe/suspicious -> 0/1/2
    print("Classes:", list(le.classes_))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000),
        "RandomForest": RandomForestClassifier(n_estimators=300, max_depth=12, random_state=42),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            use_label_encoder=False, eval_metric="mlogloss", random_state=42
        ),
    }

    results = {}
    trained_models = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, average="macro", zero_division=0)
        rec = recall_score(y_test, preds, average="macro", zero_division=0)
        f1 = f1_score(y_test, preds, average="macro", zero_division=0)
        cm = confusion_matrix(y_test, preds)

        results[name] = {
            "accuracy": round(acc, 4),
            "precision_macro": round(prec, 4),
            "recall_macro": round(rec, 4),
            "f1_macro": round(f1, 4),
        }
        trained_models[name] = model

        # Confusion matrix plot
        fig, ax = plt.subplots(figsize=(5, 4))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks(range(len(le.classes_)))
        ax.set_yticks(range(len(le.classes_)))
        ax.set_xticklabels(le.classes_, rotation=45)
        ax.set_yticklabels(le.classes_)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title(f"Confusion Matrix - {name}")
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, cm[i, j], ha="center", va="center", color="black")
        fig.colorbar(im)
        fig.tight_layout()
        fig.savefig(f"{MODEL_DIR}/confusion_matrix_{name}.png", dpi=120)
        plt.close(fig)

        print(f"\n=== {name} ===")
        print(results[name])
        print(classification_report(y_test, preds, target_names=le.classes_, zero_division=0))

    # --- Select best model by macro F1 ---
    best_name = max(results, key=lambda k: results[k]["f1_macro"])
    best_model = trained_models[best_name]
    print(f"\nBest model selected: {best_name} (macro F1 = {results[best_name]['f1_macro']})")

    # --- Feature importance plot for best tree-based model (or coef for LR) ---
    fig, ax = plt.subplots(figsize=(7, 5))
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
    else:
        importances = np.abs(best_model.coef_).mean(axis=0)
    order = np.argsort(importances)[::-1]
    ax.barh([FEATURE_COLUMNS[i] for i in order][::-1], importances[order][::-1], color="#4C72B0")
    ax.set_title(f"Feature Importance - {best_name}")
    fig.tight_layout()
    fig.savefig(f"{MODEL_DIR}/feature_importance.png", dpi=120)
    plt.close(fig)

    # --- Model comparison bar chart ---
    fig, ax = plt.subplots(figsize=(7, 5))
    metrics_names = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    x = np.arange(len(metrics_names))
    width = 0.25
    for i, (name, res) in enumerate(results.items()):
        vals = [res[m] for m in metrics_names]
        ax.bar(x + i * width, vals, width, label=name)
    ax.set_xticks(x + width)
    ax.set_xticklabels(metrics_names)
    ax.set_ylim(0, 1.05)
    ax.legend()
    ax.set_title("Model Comparison")
    fig.tight_layout()
    fig.savefig(f"{MODEL_DIR}/model_comparison.png", dpi=120)
    plt.close(fig)

    # --- Save artifacts ---
    for name, trained_model in trained_models.items():
        joblib.dump(trained_model, os.path.join(MODEL_DIR, f"model_{name}.joblib"))

    joblib.dump(best_model, f"{MODEL_DIR}/best_model.joblib")
    joblib.dump(le, f"{MODEL_DIR}/label_encoder.joblib")
    with open(f"{MODEL_DIR}/metrics.json", "w") as f:
        json.dump({"results": results, "best_model": best_name,
                   "feature_columns": FEATURE_COLUMNS,
                   "classes": list(le.classes_)}, f, indent=2)

    print("\nSaved: model_*.joblib, best_model.joblib, label_encoder.joblib, metrics.json, plots (*.png)")


if __name__ == "__main__":
    main()
