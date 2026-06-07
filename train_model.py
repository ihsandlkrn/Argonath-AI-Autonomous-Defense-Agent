"""
train_model.py — Phase 2: Multi-class Model + Cross-Validation (Pure-ML)
══════════════════════════════════════════════════════════════════════════
What's new in this version:
  - Pure-ML architecture — no rule engine.
  - Reads from 'models/balanced_data.csv' produced by data_pipeline.py
    (6 Scapy-compatible timing/ratio features).
  - Trains both binary (BENIGN vs ATTACK) and multi-class models.
  - Applies StratifiedKFold cross-validation for stability checks.
"""

import numpy as np
import pandas as pd
import joblib
import time
import os
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)

import warnings
warnings.filterwarnings('ignore')

# ──────────────────────────────────────────────────────────────────────────────
def load_data():
    """Loads the balanced dataset from CSV and extracts features/labels."""
    print("Step 1 — Loading balanced dataset...")
    data_path = 'models/balanced_data.csv'

    if not os.path.exists(data_path):
        print(f"ERROR: {data_path} not found!")
        return None, None, None, None, None

    try:
        class_names   = joblib.load('models/class_names.pkl')
        feature_names = joblib.load('models/feature_names.pkl')
    except FileNotFoundError:
        print("ERROR: Metadata .pkl files not found. Run data_pipeline.py first.")
        return None, None, None, None, None

    df       = pd.read_csv(data_path)
    X        = df[feature_names].values
    y_multi  = df['Label'].values
    y_binary = np.where(y_multi == 0, 0, 1)

    attack_rate = y_binary.mean() * 100
    print(f"  Flows    : {X.shape[0]:,}  |  Features: {X.shape[1]}")
    print(f"  Attack   : {attack_rate:.1f}%  Benign: {100 - attack_rate:.1f}%")

    return X, y_binary, y_multi, class_names, feature_names


# ──────────────────────────────────────────────────────────────────────────────
def cross_validate(model, X_train, y_train, label=""):
    """5-fold stratified cross-validation for stability checking."""
    print(f"\n  Running 5-fold CV{' (' + label + ')' if label else ''}...")
    skf    = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    t0     = time.time()
    # Weighted F1 is the most appropriate metric for imbalanced cybersecurity data
    scores = cross_val_score(model, X_train, y_train,
                             cv=skf, scoring='f1_weighted', n_jobs=-1)
    elapsed = time.time() - t0

    sep = "─" * 55
    print(f"\n{sep}")
    print(f"CROSS-VALIDATION  {label}")
    print(sep)
    for i, s in enumerate(scores, 1):
        bar = "█" * int(s * 40)
        print(f"  Fold {i}:  {s:.4f}  {bar}")
    print(f"  {'─'*46}")
    print(f"  Mean F1 (weighted): {scores.mean():.4f}  ± {scores.std():.4f}")
    print(f"  Time: {elapsed:.1f}s")
    print(sep)

    status = ("✅ Stable, not overfitting." if scores.std() < 0.01
              else "✅ Acceptable variance." if scores.std() < 0.03
              else "⚠️  High variance — consider tuning.")
    print(f"  {status}")
    return scores.mean(), scores.std()


# ──────────────────────────────────────────────────────────────────────────────
def train_binary(X_train, X_test, y_train, y_test):
    """
    Trains the core binary model (BENIGN vs ATTACK).
    Primary decision-maker of the autonomous agent.
    """
    sep = "=" * 60
    print(f"\n{sep}")
    print("BINARY MODEL  (BENIGN vs ATTACK)")
    print(sep)

    print("\nStep 2a — Training Random Forest (binary)...")
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=20,
                                class_weight='balanced',
                                random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_time = time.time() - t0
    print(f"  Done in {rf_time:.1f}s")

    y_pred = rf.predict(X_test)
    f1  = f1_score(y_test, y_pred)
    pr  = precision_score(y_test, y_pred)
    re  = recall_score(y_test, y_pred)
    cm  = confusion_matrix(y_test, y_pred)

    print(classification_report(y_test, y_pred,
                                target_names=['BENIGN', 'ATTACK']))
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}  FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    print(f"  False positive rate : {cm[0][1]/(cm[0][0]+cm[0][1])*100:.2f}%")
    print(f"  Miss rate           : {cm[1][0]/(cm[1][0]+cm[1][1])*100:.2f}%")

    return rf, f1, pr, re, cm


# ──────────────────────────────────────────────────────────────────────────────
def train_multiclass(X_train, X_test, y_train_m, y_test_m, class_names):
    """
    Trains the multi-class model to predict specific attack types
    (DoS, DDoS, Port Scan, Brute Force, Web Attack, Bot, Infiltration).
    """
    sep = "=" * 60
    print(f"\n{sep}")
    print("MULTI-CLASS MODEL  (8 classes: BENIGN + 7 attack types)")
    print(sep)

    print(f"\nStep 2b — Training Random Forest (multi-class)...")
    t0 = time.time()
    rf_multi = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_multi.fit(X_train, y_train_m)
    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s")

    y_pred_m        = rf_multi.predict(X_test)
    present_classes = sorted(np.unique(np.concatenate([y_test_m, y_pred_m])))
    present_names   = [class_names.get(i, f"Class{i}") for i in present_classes]

    print(f"\n{sep}")
    print("MULTI-CLASS PERFORMANCE REPORT")
    print(sep)
    print(classification_report(y_test_m, y_pred_m,
                                labels=present_classes,
                                target_names=present_names,
                                zero_division=0))

    print("  📊 Generating chart: Multi_Class_Confusion_Matrix.png")
    plot_confusion_matrix(y_test_m, y_pred_m, present_names, "Multi Class Confusion Matrix")

    # Export classification report as CSV for academic reporting
    report_dict = classification_report(y_test_m, y_pred_m, labels=present_classes,
                                        target_names=present_names,
                                        zero_division=0, output_dict=True)
    pd.DataFrame(report_dict).transpose().to_csv("MultiClass_Classification_Report.csv", sep=";")

    f1_m = f1_score(y_test_m, y_pred_m, average='weighted')
    print(f"\n  Weighted F1-Score: {f1_m:.4f}  ({f1_m*100:.2f}%)")
    print(sep)

    return rf_multi, f1_m


# ──────────────────────────────────────────────────────────────────────────────
def save_artifacts(rf_binary, rf_multi, X_test, y_test_b, y_test_m,
                   f1_b, pr_b, re_b, cm_b):
    """Exports all trained models and metrics for the live agent."""
    print("\nStep 3 — Saving artifacts...")
    os.makedirs('models', exist_ok=True)

    joblib.dump(rf_binary, 'models/agent_brain.pkl')
    joblib.dump(rf_multi,  'models/agent_brain_multi.pkl')
    # scaler and feature_names.pkl are already saved by data_pipeline.py

    np.save('models/rf_metrics.npy', np.array([
        pr_b, re_b, f1_b,
        cm_b[0][0], cm_b[0][1], cm_b[1][0], cm_b[1][1]
    ]))

    print("  ✅ models/agent_brain.pkl          (binary model)")
    print("  ✅ models/agent_brain_multi.pkl    (multi-class model)")


# ──────────────────────────────────────────────────────────────────────────────
def train_agent_brain():
    """Main training pipeline."""

    X, y_binary, y_multi, class_names, feature_names = load_data()
    if X is None:
        return

    print("\nStep 1b — Splitting into train (80%) / test (20%)...")
    X_train, X_test, yb_train, yb_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )
    _, _, ym_train, ym_test = train_test_split(
        X, y_multi, test_size=0.2, random_state=42, stratify=y_binary
    )
    print(f"  Train samples: {len(X_train):,}   Test samples: {len(X_test):,}")

    # SMOTE was already applied in data_pipeline.py — not needed here

    rf_cv = RandomForestClassifier(n_estimators=100, max_depth=20,
                                   class_weight='balanced',
                                   random_state=42, n_jobs=-1)
    cv_mean_b, cv_std_b = cross_validate(rf_cv, X_train, yb_train, "Binary")

    rf_cv_m = RandomForestClassifier(n_estimators=100, max_depth=20,
                                     class_weight='balanced',
                                     random_state=42, n_jobs=-1)
    cv_mean_m, cv_std_m = cross_validate(rf_cv_m, X_train, ym_train, "Multi-class")

    rf_b, f1_b, pr_b, re_b, cm_b = train_binary(X_train, X_test, yb_train, yb_test)
    rf_m, f1_m = train_multiclass(X_train, X_test, ym_train, ym_test, class_names)

    print("\n  📊 Generating chart: Feature_Importance.png")
    plot_feature_importance(rf_b, feature_names, top_n=6)

    sep = "─" * 55
    print(f"\n{sep}")
    print("OVERFITTING CHECK")
    print(sep)
    print(f"  Binary model:")
    print(f"    CV F1    : {cv_mean_b:.4f} ± {cv_std_b:.4f}")
    print(f"    Test F1  : {f1_b:.4f}")
    print(f"    Gap      : {abs(cv_mean_b-f1_b):.4f}  "
          f"{'✅ OK' if abs(cv_mean_b-f1_b) < 0.02 else '⚠️  Check'}")
    print(f"\n  Multi-class model:")
    print(f"    CV F1    : {cv_mean_m:.4f} ± {cv_std_m:.4f}")
    print(f"    Test F1  : {f1_m:.4f}")
    print(f"    Gap      : {abs(cv_mean_m-f1_m):.4f}  "
          f"{'✅ OK' if abs(cv_mean_m-f1_m) < 0.02 else '⚠️  Check'}")
    print(sep)

    save_artifacts(rf_b, rf_m, X_test, yb_test, ym_test, f1_b, pr_b, re_b, cm_b)


# ──────────────────────────────────────────────────────────────────────────────
# VISUALISATION HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def plot_confusion_matrix(y_true, y_pred, class_names, title="Confusion Matrix"):
    """Plots a normalised confusion matrix as a percentage heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    # Normalise each row to percentages
    cm_pct = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm_pct, annot=True, fmt=".2%", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names)
    plt.title(title, fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    plt.savefig(f"{title.replace(' ', '_')}.png", dpi=300)

# Usage: plot_confusion_matrix(y_test_m, y_pred_m, list(class_names.values()), "Multi Class Confusion Matrix")


def plot_feature_importance(rf_model, feature_names, top_n=15):
    """Plots the top-N feature importances from a trained Random Forest."""
    importances = rf_model.feature_importances_
    indices     = np.argsort(importances)[::-1][:top_n]
    top_features    = [feature_names[i] for i in indices]
    top_importances = importances[indices]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_importances, y=top_features, palette="viridis")
    plt.title(f"Top {top_n} Feature Importances (Random Forest)", fontsize=14, fontweight='bold')
    plt.xlabel('Gini Importance', fontsize=12)
    plt.ylabel('Feature', fontsize=12)
    plt.tight_layout()
    plt.savefig("Feature_Importance.png", dpi=300)

# Usage: plot_feature_importance(rf_binary, MANUAL_FEATURES, top_n=6)


if __name__ == "__main__":
    train_agent_brain()