import json
import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from feature_extractor import extract_features

ANALYSES_DIR = "/opt/CAPEv2/storage/analyses"
MODEL_PATH = "/opt/CAPEv2/ml/model.pkl"
LABELS = {
    "15": 1,  # WannaCry = malware
    "14": 1,  # WannaCry = malware
    "12": 0,  # EICAR = benign
    "3": 0,   # EICAR = benign (from earlier)
}

def load_dataset():
    X, y = [], []
    feature_names = None
    for task_id, label in LABELS.items():
        report_path = f"{ANALYSES_DIR}/{task_id}/reports/report.json"
        if not os.path.exists(report_path):
            print(f"Skipping task {task_id} - no report")
            continue
        try:
            features = extract_features(report_path)
            if feature_names is None:
                feature_names = list(features.keys())
            X.append(list(features.values()))
            y.append(label)
            print(f"Task {task_id}: label={label}, features={features}")
        except Exception as e:
            print(f"Error task {task_id}: {e}")
    return np.array(X), np.array(y), feature_names

def train():
    X, y, feature_names = load_dataset()
    print(f"\nDataset: {len(X)} samples — {sum(y)} malware, {len(y)-sum(y)} benign")

    if len(X) < 2:
        print("Need more samples.")
        return

    if len(set(y)) < 2:
        print("Need both malware and benign samples.")
        return

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    preds = clf.predict(X)
    print(f"Training accuracy: {accuracy_score(y, preds):.2f}")
    print(classification_report(y, preds, target_names=["benign", "malware"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "feature_names": feature_names}, f)
    print(f"Model saved: {MODEL_PATH}")

if __name__ == "__main__":
    train()
