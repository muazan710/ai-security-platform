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

# ✅ FIX: Correct import from features.py
try:
    from features import extract_features, FEATURE_COLUMNS
    print("✅ Features imported successfully")
    print(f"📋 Feature columns: {FEATURE_COLUMNS}")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "dataset", "phishing_dataset.csv")
MODEL_DIR = os.path.dirname(__file__)


def build_feature_table(df):
    """Extract features from all URLs in dataframe"""
    rows = []
    for url in df["url"]:
        feats = extract_features(url)
        # Ensure all FEATURE_COLUMNS are present
        row = {k: feats.get(k, 0) for k in FEATURE_COLUMNS}
        rows.append(row)
    X = pd.DataFrame(rows)
    return X


def main():
    print("=" * 60)
    print("🚀 AI Security Intelligence Platform - Model Training")
    print("=" * 60)

    # ============================================
    # 1. LOAD DATASET
    # ============================================
    print("\n📂 Loading dataset...")
    if not os.path.exists(DATA_PATH):
        print(f"❌ Dataset not found at: {DATA_PATH}")
        print("Please ensure dataset exists at: dataset/phishing_dataset.csv")
        sys.exit(1)
    
    df = pd.read_csv(DATA_PATH)
    print(f"✅ Loaded {len(df)} rows")
    print("\n📊 Label Distribution:")
    print(df["label"].value_counts())

    # ============================================
    # 2. DATA CLEANING
    # ============================================
    print("\n🧹 Cleaning data...")
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset="url")
    print(f"✅ After cleaning: {len(df)} rows")

    # ============================================
    # 3. FEATURE EXTRACTION
    # ============================================
    print("\n🔧 Extracting features...")
    X = build_feature_table(df)
    print(f"✅ Extracted {X.shape[1]} features from {X.shape[0]} URLs")
    print(f"📋 Feature columns: {FEATURE_COLUMNS}")

    # ============================================
    # 4. ENCODE LABELS
    # ============================================
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    print(f"\n📊 Classes: {list(le.classes_)}")
    print(f"   Encoded: 0={le.classes_[0]}, 1={le.classes_[1]}, 2={le.classes_[2]}")

    # ============================================
    # 5. TRAIN-TEST SPLIT
    # ============================================
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n📊 Train: {len(X_train)} rows, Test: {len(X_test)} rows")

    # ============================================
    # 6. DEFINE MODELS (FIXED)
    # ============================================
    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0
            # ✅ REMOVED: multi_class parameter (sklearn version mismatch)
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, 
            max_depth=12, 
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300, 
            max_depth=6, 
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False, 
            eval_metric="mlogloss", 
            random_state=42
        ),
    }

    results = {}
    trained_models = {}

    # ============================================
    # 7. TRAIN ALL MODELS
    # ============================================
    print("\n🚀 Training models...")
    print("-" * 60)

    for name, model in models.items():
        print(f"\n📊 Training {name}...")
        model.fit(X_train, y_train)
        trained_models[name] = model
        
        # Predictions
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)
        
        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "accuracy": round(acc, 4),
            "precision_macro": round(prec, 4),
            "recall_macro": round(rec, 4),
            "f1_macro": round(f1, 4),
            "confusion_matrix": cm.tolist()
        }

        print(f"   ✅ Accuracy:  {acc:.4f}")
        print(f"   ✅ Precision: {prec:.4f}")
        print(f"   ✅ Recall:    {rec:.4f}")
        print(f"   ✅ F1 Score:  {f1:.4f}")
        
        # Show per-class metrics
        print(f"\n   📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

        # ============================================
        # 8. CONFUSION MATRIX PLOT
        # ============================================
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
        fig.savefig(os.path.join(MODEL_DIR, f"confusion_matrix_{name}.png"), dpi=120)
        plt.close(fig)

    # ============================================
    # 9. SELECT BEST MODEL
    # ============================================
    best_name = max(results, key=lambda k: results[k]["f1_macro"])
    best_model = trained_models[best_name]
    print(f"\n🏆 Best model selected: {best_name}")
    print(f"   F1 Score: {results[best_name]['f1_macro']:.4f}")
    print(f"   Accuracy: {results[best_name]['accuracy']:.4f}")

    # ============================================
    # 10. FEATURE IMPORTANCE PLOT
    # ============================================
    fig, ax = plt.subplots(figsize=(8, 6))
    
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        title = f"Feature Importance - {best_name} (Gain)"
    elif hasattr(best_model, "coef_"):
        importances = np.abs(best_model.coef_).mean(axis=0)
        title = f"Feature Importance - {best_name} (|Coefficients|)"
    else:
        importances = np.ones(len(FEATURE_COLUMNS))
        title = f"Feature Importance - {best_name}"
    
    order = np.argsort(importances)[::-1]
    sorted_features = [FEATURE_COLUMNS[i] for i in order]
    sorted_importances = importances[order]
    
    ax.barh(sorted_features[::-1], sorted_importances[::-1], color="#4C72B0")
    ax.set_xlabel("Importance")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, "feature_importance.png"), dpi=120)
    plt.close(fig)

    # ============================================
    # 11. MODEL COMPARISON PLOT
    # ============================================
    fig, ax = plt.subplots(figsize=(8, 5))
    metrics_names = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    x = np.arange(len(metrics_names))
    width = 0.25
    
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1']
    for i, (name, res) in enumerate(results.items()):
        vals = [res.get(m, 0) for m in metrics_names]
        ax.bar(x + i * width, vals, width, label=name, color=colors[i])
    
    ax.set_xticks(x + width)
    ax.set_xticklabels([m.replace('_', ' ').title() for m in metrics_names])
    ax.set_ylim(0, 1.05)
    ax.legend(loc='lower right')
    ax.set_title("Model Comparison")
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, "model_comparison.png"), dpi=120)
    plt.close(fig)

    # ============================================
    # 12. SAVE ARTIFACTS
    # ============================================
    print("\n💾 Saving models...")
    
    # Save all 3 models
    for name, trained_model in trained_models.items():
        model_path = os.path.join(MODEL_DIR, f"model_{name}.joblib")
        joblib.dump(trained_model, model_path)
        print(f"  ✅ Saved: model_{name}.joblib")

    # Save best model
    joblib.dump(best_model, os.path.join(MODEL_DIR, "best_model.joblib"))
    print(f"  ✅ Saved: best_model.joblib")

    # Save label encoder
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.joblib"))
    print(f"  ✅ Saved: label_encoder.joblib")

    # Save metrics
    metrics = {
        "results": results,
        "best_model": best_name,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(le.classes_)
    }
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  ✅ Saved: metrics.json")

    # ============================================
    # 13. FINAL SUMMARY
    # ============================================
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS SUMMARY")
    print("=" * 60)
    print(f"\n📂 Models saved in: {MODEL_DIR}")
    print(f"\n🏆 Best Model: {best_name}")
    print(f"   F1 Score: {results[best_name]['f1_macro']:.4f}")
    print(f"   Accuracy: {results[best_name]['accuracy']:.4f}")
    
    print("\n📊 All Models:")
    for name, res in results.items():
        print(f"   {name}: F1={res['f1_macro']:.4f}, Acc={res['accuracy']:.4f}")

    print("\n📁 Saved Files:")
    print("   - model_LogisticRegression.joblib")
    print("   - model_RandomForest.joblib")
    print("   - model_XGBoost.joblib")
    print("   - best_model.joblib")
    print("   - label_encoder.joblib")
    print("   - metrics.json")
    print("   - confusion_matrix_*.png")
    print("   - feature_importance.png")
    print("   - model_comparison.png")
    print("\n" + "=" * 60)
    print("✅ Training Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()