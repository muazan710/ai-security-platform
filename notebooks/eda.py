# EDA / Data Analysis — AI Security Intelligence Platform
#
# This is provided as an annotated script (run as a normal .py or paste into
# Jupyter cell-by-cell). It covers: data cleaning check, missing values,
# class balance, and feature distributions by class — satisfying "Part 1:
# Data cleaning, missing value handling, feature analysis, data
# visualization."

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "model"))

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from features import extract_feature_vector, FEATURE_COLUMNS

DATA_PATH = "/home/claude/project/dataset/phishing_dataset.csv"
OUT_DIR = "/home/claude/project/notebooks"

df = pd.read_csv(DATA_PATH)
print("Shape:", df.shape)
print("\nMissing values:\n", df.isnull().sum())
print("\nDuplicate URLs:", df["url"].duplicated().sum())
print("\nClass balance:\n", df["label"].value_counts())

# Build feature table for analysis
feat_rows = [extract_feature_vector(u) for u in df["url"]]
X = pd.DataFrame(feat_rows)
X["label"] = df["label"].values

# Class balance plot
fig, ax = plt.subplots(figsize=(5, 4))
df["label"].value_counts().plot(kind="bar", ax=ax, color=["#ef4444", "#22c55e", "#f59e0b"])
ax.set_title("Class Balance")
ax.set_ylabel("Count")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/class_balance.png", dpi=120)
plt.close(fig)

# Distribution of a few key features by class
key_feats = ["url_length", "num_suspicious_keywords", "subdomain_count", "entropy"]
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
for ax, feat in zip(axes.flat, key_feats):
    for label, color in zip(["safe", "suspicious", "malicious"], ["#22c55e", "#f59e0b", "#ef4444"]):
        subset = X[X["label"] == label][feat]
        ax.hist(subset, bins=20, alpha=0.5, label=label, color=color)
    ax.set_title(feat)
    ax.legend(fontsize=8)
fig.suptitle("Feature Distributions by Class")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/feature_distributions.png", dpi=120)
plt.close(fig)

print("\nSaved: class_balance.png, feature_distributions.png")
print("\nSummary stats by class:\n", X.groupby("label")[key_feats].mean())
