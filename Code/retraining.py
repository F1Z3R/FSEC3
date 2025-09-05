import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
import xgboost as xgb  # only for type checks

# -----------------------------
# Paths
# -----------------------------
CURRENT_MODEL_PATH = "Model/current_model.joblib"
ORIGINAL_MODEL_PATH = "Model/original_model.joblib"
SCALER_PATH = "Model/scaler.joblib"
PCA_PATH = "Model/pca.joblib"   # optional, will be used if present
FP_CSV = "Model/FP.csv"
FP_GLOBAL_CSV = "Model/FP-Global.csv"

# -----------------------------
# Load scaler and (optionally) PCA
# -----------------------------
print("[INFO] Loading scaler...")
scaler = joblib.load(SCALER_PATH)
print("[INFO] Scaler loaded.")

pca = None
if os.path.isfile(PCA_PATH):
    try:
        pca = joblib.load(PCA_PATH)
        print("[INFO] PCA loaded.")
    except Exception as e:
        print(f"[WARN] Could not load PCA: {e}. Proceeding without PCA.")
else:
    print("[INFO] No PCA found; proceeding without PCA.")

# -----------------------------
# Model IO
# -----------------------------
def load_model(path):
    if not os.path.isfile(path):
        print(f"[WARN] Model {path} not found.")
        return None
    print(f"[INFO] Loading model from {path}...")
    model = joblib.load(path)
    print("[INFO] Model loaded.")
    return model

def save_model(model, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    print(f"[INFO] Model saved to {path}")

# -----------------------------
# Data Cleaning
# -----------------------------
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise ValueError("Input DataFrame is empty.")

    bulk_cols = [
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate'
    ]
    cols_to_drop = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Protocol', 'Timestamp', 'Label']
    drop_me = [c for c in (bulk_cols + cols_to_drop) if c in df.columns]
    df = df.drop(columns=drop_me, errors="ignore")

    df = df.drop_duplicates()
    df = df.replace([np.inf, -np.inf], np.nan)

    if "Flow Bytes/s" in df.columns:
        df["Flow Bytes/s"] = df["Flow Bytes/s"].fillna(df["Flow Bytes/s"].median())
    if "Flow Packets/s" in df.columns:
        df["Flow Packets/s"] = df["Flow Packets/s"].fillna(df["Flow Packets/s"].median())

    return df

# -----------------------------
# Interactive Downsampling
# -----------------------------
def interactive_downsample(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise ValueError("DataFrame is empty, cannot downsample.")
    if "Prediction" not in df.columns:
        raise KeyError("Expected label column 'Prediction' not found.")

    print("\n[INFO] Class distribution before downsampling:")
    print(df['Prediction'].value_counts())

    max_samples_in = input("Enter max samples per class (default 1500): ").strip()
    max_samples = int(max_samples_in) if max_samples_in.isdigit() else 1500

    parts = []
    for label in df['Prediction'].unique():
        df_class = df[df['Prediction'] == label]
        if len(df_class) > max_samples:
            df_class = df_class.sample(n=max_samples, random_state=0)
        parts.append(df_class)

    df_out = pd.concat(parts, ignore_index=True)
    print("[INFO] Class distribution after downsampling:")
    print(df_out['Prediction'].value_counts())
    return df_out

# -----------------------------
# SMOTE Balancing
# -----------------------------
def apply_smote(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise ValueError("DataFrame is empty, cannot apply SMOTE.")
    if "Prediction" not in df.columns:
        raise KeyError("Expected label column 'Prediction' not found.")

    class_counts = df["Prediction"].value_counts()
    max_count = class_counts.max()
    sampling_strategy = {label: max_count for label in class_counts.index}

    X = df.drop("Prediction", axis=1)
    y = df["Prediction"]

    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=0)
    X_res, y_res = smote.fit_resample(X, y)

    df_balanced = pd.DataFrame(X_res, columns=X.columns)
    df_balanced["Prediction"] = y_res
    df_balanced = df_balanced.sample(frac=1, random_state=0)

    print("[INFO] Class distribution after SMOTE:")
    print(df_balanced["Prediction"].value_counts())
    return df_balanced

# -----------------------------
# Feature Alignment helper
# -----------------------------
def align_features_to_scaler(X: pd.DataFrame) -> pd.DataFrame:
    if hasattr(scaler, "feature_names_in_"):
        expected = list(scaler.feature_names_in_)
        X_aligned = X.reindex(columns=expected, fill_value=0)
        return X_aligned
    return X

# -----------------------------
# Incremental Training
# -----------------------------
def incremental_train(df: pd.DataFrame, old_model_path: str):
    try:
        df = clean_data(df)

        # Ensure 'Prediction' column exists
        if "Attack Type" in df.columns and "Prediction" not in df.columns:
            df = df.rename(columns={"Attack Type": "Prediction"})
        if "Prediction" not in df.columns:
            raise KeyError("Label column 'Prediction' is missing.")

        df = interactive_downsample(df)
        df = apply_smote(df)

        X_new = df.drop("Prediction", axis=1)
        y_new = df["Prediction"]

        X_new = align_features_to_scaler(X_new)
        X_scaled = scaler.transform(X_new)

        if pca is not None:
            X_final = pca.transform(X_scaled)
        else:
            X_final = X_scaled

        le = LabelEncoder()
        y_enc = le.fit_transform(y_new)

        old_model = load_model(old_model_path)

        if old_model is None or not isinstance(old_model, XGBClassifier):
            print("[INFO] Training new XGBClassifier...")
            model = XGBClassifier(
                objective="multi:softmax",
                max_depth=5,
                learning_rate=0.2,
                colsample_bytree=0.85,
                subsample=1.0,
                min_child_weight=1,
                eval_metric="mlogloss",
                n_estimators=500,
                random_state=0
            )
        else:
            print("[INFO] Incremental training with warm_start...")
            model = old_model
            model.set_params(n_estimators=model.n_estimators + 100, warm_start=True)

        model.fit(X_final, y_enc)
        save_model(model, CURRENT_MODEL_PATH)

    except Exception as e:
        print(f"[ERROR] Incremental training failed: {e}")

# -----------------------------
# Retraining Menu
# -----------------------------
def retrain_model():
    print("Retraining Menu:")
    print("1 - Small Training (FP.csv)")
    print("2 - Big Training (FP-Global.csv)")
    choice = input("Enter choice: ").strip()

    try:
        if choice == "1":
            if not os.path.isfile(FP_CSV) or os.path.getsize(FP_CSV) == 0:
                print(f"[WARN] {FP_CSV} not found or empty.")
                return
            df = pd.read_csv(FP_CSV)
            incremental_train(df, CURRENT_MODEL_PATH)
            open(FP_CSV, 'w').close()

        elif choice == "2":
            if not os.path.isfile(FP_GLOBAL_CSV) or os.path.getsize(FP_GLOBAL_CSV) == 0:
                print(f"[WARN] {FP_GLOBAL_CSV} not found or empty.")
                return
            df = pd.read_csv(FP_GLOBAL_CSV)
            incremental_train(df, ORIGINAL_MODEL_PATH)

        else:
            print("[WARN] Invalid choice.")

    except Exception as e:
        print(f"[ERROR] Retraining failed: {e}")
