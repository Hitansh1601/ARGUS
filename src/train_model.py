from pathlib import Path

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

_CFG = load_config() if load_config else {}
_DATA_CFG = _CFG.get("data", {})
_MODEL_CFG = _CFG.get("model", {})
_EVAL_CFG = _CFG.get("eval", {})

INPUT_FILE = BASE_DIR / _DATA_CFG.get("features", "data/processed/argus_features.csv")

RESULTS_DIR = BASE_DIR / _DATA_CFG.get("results_dir", "results")
MODEL_DIR = BASE_DIR / "models"

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def main():

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

    # -----------------------------------------------------
    # Target
    # -----------------------------------------------------

    y = df["label"].astype(int)

    # -----------------------------------------------------
    # Metadata that MUST NOT be used as ML features
    # -----------------------------------------------------

    metadata_columns = [
        "label",
        "scenario",
        "dominant_phase",
        "run_id",
        "host_id",
        "window_id",
    ]

    X = df.drop(
        columns=metadata_columns,
        errors="ignore"
    )

    # Keep numeric features only
    X = X.select_dtypes(
        include=["number"]
    )

    X = X.fillna(0)

    groups = df["run_id"]

    # -----------------------------------------------------
    # Group-aware train/test split
    # -----------------------------------------------------

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=_EVAL_CFG.get("test_size", 0.25),
        random_state=_EVAL_CFG.get("random_state", 42),
    )

    train_idx, test_idx = next(
        splitter.split(
            X,
            y,
            groups=groups
        )
    )

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    print()
    print("Training windows:", len(X_train))
    print("Testing windows :", len(X_test))

    print()
    print("Training class balance:")
    print(y_train.value_counts())

    print()
    print("Testing class balance:")
    print(y_test.value_counts())

    # -----------------------------------------------------
    # Model
    # -----------------------------------------------------

    print()
    print("Training XGBoost...")
    log.info("hyperparams=%s", _MODEL_CFG or "defaults")

    model = XGBClassifier(
        n_estimators=int(_MODEL_CFG.get("n_estimators", 250)),
        max_depth=int(_MODEL_CFG.get("max_depth", 5)),
        learning_rate=float(_MODEL_CFG.get("learning_rate", 0.05)),
        subsample=float(_MODEL_CFG.get("subsample", 0.9)),
        colsample_bytree=float(_MODEL_CFG.get("colsample_bytree", 0.9)),
        objective=_MODEL_CFG.get("objective", "binary:logistic"),
        eval_metric=_MODEL_CFG.get("eval_metric", "logloss"),
        random_state=int(_MODEL_CFG.get("random_state", 42)),
        n_jobs=int(_MODEL_CFG.get("n_jobs", 1)),  # n_jobs>1 is ~100x slower on Windows/OpenMP
        tree_method=_MODEL_CFG.get("tree_method", "hist"),
    )

    model.fit(
        X_train,
        y_train,
    )

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    predictions = (
        probabilities >= 0.5
    ).astype(int)

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    auc = roc_auc_score(
        y_test,
        probabilities,
    )

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
        "feature": X.columns,
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


if __name__ == "__main__":
    main()