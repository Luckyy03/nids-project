import pandas as pd
import numpy as np
import joblib, os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

MODEL_PATH = "models/nids_model.pkl"
ENC_PATH   = "models/encoders.pkl"
os.makedirs("models", exist_ok=True)

COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]
CAT_COLS = ["protocol_type", "service", "flag"]

def load_data(path):
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df.drop("difficulty", axis=1, inplace=True)
    # Simplify: normal vs attack (binary classification)
    df["label"] = df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
    return df

def preprocess(df, encoders=None, fit=True):
    df = df.copy()
    if fit:
        encoders = {}
        for col in CAT_COLS:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
        le_label = LabelEncoder()
        df["label"] = le_label.fit_transform(df["label"])
        encoders["label"] = le_label
    else:
        for col in CAT_COLS:
            df[col] = encoders[col].transform(df[col])
        df["label"] = encoders["label"].transform(df["label"])
    X = df.drop("label", axis=1)
    y = df["label"]
    return X, y, encoders

def train():
    print("[*] Loading training data...")
    train_df = load_data("data/KDDTrain+.txt")
    test_df  = load_data("data/KDDTest+.txt")
    X_train, y_train, encoders = preprocess(train_df, fit=True)
    X_test,  y_test, _         = preprocess(test_df, encoders=encoders, fit=False)
    print("[*] Training Random Forest (this takes ~1-2 minutes)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(f"[+] Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["attack","normal"]))
    joblib.dump(model, MODEL_PATH)
    joblib.dump(encoders, ENC_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")
    return model, encoders

def load_model():
    return joblib.load(MODEL_PATH), joblib.load(ENC_PATH)

def predict_packet(features: dict, model, encoders):
    """features = dict with same keys as COLUMNS (minus label/difficulty)"""
    try:
        row = pd.DataFrame([features])
        for col in CAT_COLS:
            if col in row.columns:
                row[col] = encoders[col].transform(row[col])
        return encoders["label"].inverse_transform(model.predict(row))[0]
    except Exception as e:
        return "unknown"

if __name__ == "__main__":
    train()
