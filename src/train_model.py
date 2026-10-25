from pathlib import Path
import argparse
import json
import logging

import matplotlib

# Use a non-GUI backend because ARGUS saves plots to files.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
)

from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

try:
    from src.config import load_config
except ImportError:  # script-run fallback
    try:
        from config import load_config
    except ImportError:
        load_config = None  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.train")


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "argus_features.csv"
)

RESULTS_DIR = BASE_DIR / "results"
MODEL_DIR = BASE_DIR / "models"

# Tunable hyperparameters: config.yaml wins, literals are fallbacks.
# (Single source of truth for training.)
_CFG = load_config() if load_config else {}
_MODEL_CFG = _CFG.get("model", {})
_EVAL_CFG = _CFG.get("eval", {})
_ALERT_CFG = _CFG.get("alerting", {})

N_ESTIMATORS = int(_MODEL_CFG.get("n_estimators", 250))
MAX_DEPTH = int(_MODEL_CFG.get("max_depth", 5))
LEARNING_RATE = float(_MODEL_CFG.get("learning_rate", 0.05))
SUBSAMPLE = float(_MODEL_CFG.get("subsample", 0.9))
COLSAMPLE_BYTREE = float(_MODEL_CFG.get("colsample_bytree", 0.9))
TEST_SIZE = float(_EVAL_CFG.get("test_size", 0.25))
RANDOM_STATE = int(_EVAL_CFG.get("random_state", 42))
THRESHOLD = float(_ALERT_CFG.get("threshold", 0.5))
# NOTE: n_jobs>1 is ~100x slower on Windows/OpenMP; keep hist + 1 job.
N_JOBS = int(_MODEL_CFG.get("n_jobs", 1))
TREE_METHOD = _MODEL_CFG.get("tree_method", "hist")

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def train_and_evaluate(df, test_size=TEST_SIZE, seed=RANDOM_STATE,
                       threshold=THRESHOLD,
                       save_plots=True, save_model_path=None):
    """Core training logic, testable without filesystem side-effects."""
    y = df["label"].astype(int)

    metadata_columns = [
        "label",
        "scenario",
        "dominant_phase",
        "run_id",
        "host_id",
        "window_id",
    ]

    X = df.drop(columns=metadata_columns, errors="ignore")
    X = X.select_dtypes(include=["number"]).fillna(0)
    groups = df["run_id"]

    splitter = GroupShuffleSplit(
        n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(X, y, groups=groups))

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    model = XGBClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        learning_rate=LEARNING_RATE,
        subsample=SUBSAMPLE,
        colsample_bytree=COLSAMPLE_BYTREE,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=seed,
        n_jobs=N_JOBS,
        tree_method=TREE_METHOD,
    )
    log.info("hyperparams=%s", {
        "n_estimators": N_ESTIMATORS, "max_depth": MAX_DEPTH,
        "learning_rate": LEARNING_RATE, "n_jobs": N_JOBS,
        "tree_method": TREE_METHOD, "threshold": threshold,
    })
    model.fit(X_train, y_train)

    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    metrics = {
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "train_windows": int(len(X_train)),
        "test_windows": int(len(X_test)),
        "threshold": threshold,
        "feature_names": list(X.columns),
    }
    return model, metrics, (X_test, y_test, probabilities, predictions)


def main(test_size=TEST_SIZE, seed=RANDOM_STATE, threshold=THRESHOLD, no_plots=False):

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "Feature file not found. "
            "Run feature_engineering.py first."
        )

    print("Loading feature dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(
        f"Total windows: {len(df):,}"
    )

    model, metrics, (X_test, y_test, probabilities, predictions) = (
        train_and_evaluate(df, test_size=test_size, seed=seed,
                             threshold=threshold)
    )

    precision = metrics["precision"]
    recall = metrics["recall"]
    f1 = metrics["f1"]
    auc = metrics["roc_auc"]
    X = pd.DataFrame(columns=metrics["feature_names"])

    print()
    print("Training windows:", metrics["train_windows"])
    print("Testing windows :", metrics["test_windows"])

    print()
    print("=" * 60)
    print("ARGUS MODEL RESULTS")
    print("=" * 60)

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"ROC-AUC   : {auc:.4f}"
    )

    print()
    print("Classification Report")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Benign",
                "Malicious"
            ],
            zero_division=0,
        )
    )

    # Save machine-readable metrics for CI gates.
    with open(RESULTS_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved {RESULTS_DIR / 'metrics.json'}")

    if no_plots:
        # Still save model + importance CSV, skip PNGs for fast tests.
        importance = pd.DataFrame({
            "feature": metrics["feature_names"],
            "importance": model.feature_importances_,
        }).sort_values("importance", ascending=False)
        importance.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)
        model.save_model(MODEL_DIR / "argus_xgboost.json")
        print("=" * 60)
        return metrics

    # -----------------------------------------------------
    # Confusion Matrix
    # -----------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions,
    )

    plt.figure(
        figsize=(7, 5)
    )

    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        xticklabels=[
            "Benign",
            "Malicious"
        ],
        yticklabels=[
            "Benign",
            "Malicious"
        ],
    )

    plt.xlabel(
        "Predicted"
    )

    plt.ylabel(
        "Actual"
    )

    plt.title(
        "ARGUS Confusion Matrix"
    )

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "argus_confusion_matrix.png",
        dpi=200,
    )

    plt.close()

    # -----------------------------------------------------
    # ROC Curve
    # -----------------------------------------------------

    fpr, tpr, _ = roc_curve(
        y_test,
        probabilities,
    )

    plt.figure(
        figsize=(7, 5)
    )

    plt.plot(
        fpr,
        tpr,
        label=f"XGBoost AUC = {auc:.4f}",
    )

    plt.plot(
        [0, 1],
        [0, 1],
        linestyle="--",
    )

    plt.xlabel(
        "False Positive Rate"
    )

    plt.ylabel(
        "True Positive Rate"
    )

    plt.title(
        "ARGUS ROC Curve"
    )

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "argus_roc_curve.png",
        dpi=200,
    )

    plt.close()

    # -----------------------------------------------------
    # Feature Importance
    # -----------------------------------------------------

    importance = pd.DataFrame({
        "feature": metrics["feature_names"],
        "importance": model.feature_importances_,
    })

    importance = importance.sort_values(
        "importance",
        ascending=False,
    )

    importance.to_csv(
        RESULTS_DIR / "feature_importance.csv",
        index=False,
    )

    plt.figure(
        figsize=(10, 7)
    )

    top_features = importance.head(15)

    plt.barh(
        top_features["feature"][::-1],
        top_features["importance"][::-1],
    )

    plt.xlabel(
        "Importance"
    )

    plt.title(
        "Top ARGUS Detection Features"
    )

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "argus_feature_importance.png",
        dpi=200,
    )

    plt.close()

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

    model_path = (
        MODEL_DIR
        / "argus_xgboost.json"
    )

    model.save_model(
        model_path
    )

    print()
    print("Saved results:")

    print(
        RESULTS_DIR / "argus_confusion_matrix.png"
    )

    print(
        RESULTS_DIR / "argus_roc_curve.png"
    )

    print(
        RESULTS_DIR / "argus_feature_importance.png"
    )

    print(
        RESULTS_DIR / "feature_importance.csv"
    )

    print()
    print(
        f"Saved model:\n{model_path}"
    )

    print("=" * 60)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train ARGUS XGBoost model")
    parser.add_argument("--test-size", type=float, default=TEST_SIZE)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument("--no-plots", action="store_true",
                        help="Skip PNG plots (faster, for tests)")
    args = parser.parse_args()
    main(test_size=args.test_size, seed=args.seed,
         threshold=args.threshold, no_plots=args.no_plots)