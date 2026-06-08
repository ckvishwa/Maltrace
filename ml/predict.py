#!/usr/bin/env python3

import sys
import os
import pickle
import pandas as pd
from feature_extractor import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

def load_model():
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)

    if isinstance(data, dict):
        clf = data.get("model", data)
        feature_cols = (
            data.get("feature_cols")
            or data.get("features")
            or data.get("feature_names")
        )
    else:
        clf = data
        feature_cols = None

    return clf, feature_cols

def predict(path):
    feats = extract_features(path)
    clf, feature_cols = load_model()

    print("=" * 60)
    print("MalTrace Prediction")
    print("=" * 60)
    print(f"Report: {path}")
    print(f"Extracted features: {len(feats)}")

    X = pd.DataFrame([feats])

    if feature_cols:
        print(f"Model feature columns: {len(feature_cols)}")
        for col in feature_cols:
            if col not in X.columns:
                X[col] = 0
        X = X[feature_cols]

    elif hasattr(clf, "feature_names_in_"):
        expected = list(clf.feature_names_in_)
        print(f"Model feature columns: {len(expected)}")
        for col in expected:
            if col not in X.columns:
                X[col] = 0
        X = X[expected]

    else:
        print("WARNING: Model has no stored feature names. Using extractor order.")
        X = X[list(feats.keys())]

    prob = clf.predict_proba(X)[0]
    pred = clf.predict(X)[0]

    verdict = "MALWARE" if pred == 1 else "BENIGN"
    benign_p = float(prob[0]) * 100
    malware_p = float(prob[1]) * 100
    confidence = max(benign_p, malware_p)

    print("-" * 60)
    print(f"VERDICT:            {verdict}")
    print(f"CONFIDENCE:         {confidence:.1f}%")
    print(f"BENIGN PROBABILITY: {benign_p:.1f}%")
    print(f"MALWARE PROBABILITY:{malware_p:.1f}%")
    print("-" * 60)

    print("Top non-zero behavioral indicators:")
    top = sorted(
        [(k, v) for k, v in feats.items() if isinstance(v, (int, float)) and v != 0],
        key=lambda x: abs(x[1]),
        reverse=True
    )[:12]

    for k, v in top:
        print(f"  {k:<30} {v}")

    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ml/predict.py <report.json>")
        sys.exit(1)

    predict(sys.argv[1])
