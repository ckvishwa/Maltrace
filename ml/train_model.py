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
    "12": 0,   # EICAR
    "15": 1,   # WannaCry
    "18": 1,   # WannaCry_rerun
    "19": 1,   # Kelihos
    "20": 1,   # njRAT
    "21": 1,   # Raccoon
    "22": 1,   # Cerber
    "23": 1,   # Cryptowall
    "24": 1,   # Locky
    "25": 1,   # Petya
    # "26": 1,   # WannaCry_Plus
    "27": 1,   # Shamoon
    # "28": 1,   # SpyEye
    "29": 1,   # Asprox
    "30": 1,   # Bladabindi
    "31": 1,   # Kovter
    "32": 1,   # AgentTesla
    "33": 1,   # Carberp
    "34": 1,   # Cridex
    # "35": 1,   # Cutwail
    "36": 1,   # Emotet
    # "37": 1,   # ZeroAccess
    "38": 1,   # ZeusBanking
    "39": 1,   # ZeusGameover
    "40": 0,   # 7zip
    "41": 0,   # Notepad++
    "43": 0,   # PuTTY
    "44": 0,   # WinDump
        "95":  0,   # ApproveChildRequest.exe
"96":  0,   # bdeunlock.exe
"97":  0,   # BitLockerWizardElev.exe
"98":  0,   # calc.exe       ← malscore 8.0 — critical FP test
"99":  0,   # conhost.exe
"100": 0,   # curl.exe
"101": 0,   # Dxpserver.exe
"102": 0,   # eudcedit.exe
"103": 0,   # ipconfig.exe
"104": 0,   # isoburn.exe
"105": 0,   # LicenseManagerShellext.exe
"106": 0,   # mmc.exe
"107": 0,   # msdt.exe
"108": 0,   # mspaint.exe    ← malscore 9.0 — hardest FP case
"109": 0,   # mstsc.exe      ← malscore 5.7
"110": 0,   # notepad.exe
"111": 0,   # PING.EXE
"112": 0,   # rdpshell.exe
"113": 0,   # rdpsign.exe
"114": 0,   # regedit.exe
"115": 0,   # ScriptRunner.exe
"116": 0,   # sfc.exe
"117": 0,   # SnippingTool.exe
"118": 0,   # svchost.exe
"119": 0,   # SystemSettingsAdminFlows.exe
"120": 0,   # Taskmgr.exe
"121": 0,   # whoami.exe
"122": 1,  # CryptoLocker_10Sep2013
# "123": 1,  # CryptoLocker_20Nov2013
"124": 1,  # CryptoLocker_22Jan2014
# "125": 1,  # Dyre
# "126": 1,  # BlackEnergy2.1
"127": 1,  # Trojan.Loadmoney
}

def load_dataset():
    X, y = [], []
    feature_names = None

    # ── Merge hardcoded LABELS + labels_auto.json ─────────────────────────
    merged = {}

    # Start with hardcoded
    for task_id, label in LABELS.items():
        merged[str(task_id)] = label

    # Override/extend with auto-pipeline labels
    labels_auto_path = os.path.join(os.path.dirname(__file__), "labels_auto.json")
    if os.path.exists(labels_auto_path):
        with open(labels_auto_path) as f:
            auto = json.load(f)
        for task_id, meta in auto.items():
            if isinstance(meta, dict):
                if not meta.get("usable", True):
                    continue
                merged[str(task_id)] = meta["label"]
            else:
                merged[str(task_id)] = int(meta)
        print(f"Loaded {len(auto)} auto labels, {sum(1 for v in auto.values() if isinstance(v,dict) and not v.get('usable',True))} skipped")

    print(f"Total merged labels: {len(merged)}")

    for task_id, label in merged.items():
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
        except Exception as e:
            print(f"Error task {task_id}: {e}")

    return np.array(X), np.array(y), feature_names

def train():
    X, y, feature_names = load_dataset()
    print(f"\nDataset: {len(X)} samples — {sum(y)} malware, {len(y)-sum(y)} benign")

    if len(X) < 4:
        print("Need more samples.")
        return

    if len(set(y)) < 2:
        print("Need both classes.")
        return

    # Cross-validation — real evaluation
    from sklearn.model_selection import StratifiedKFold, cross_validate
    from sklearn.metrics import make_scorer, precision_score, recall_score, f1_score

    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = {
        "accuracy":  "accuracy",
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score, zero_division=0),
        "f1":        make_scorer(f1_score, zero_division=0),
    }

    print("\nRunning 5-fold cross-validation...")
    results = cross_validate(clf, X, y, cv=cv, scoring=scoring)

    print(f"\n{'='*45}")
    print(f"  CV Accuracy  : {results['test_accuracy'].mean():.3f} ± {results['test_accuracy'].std():.3f}")
    print(f"  CV Precision : {results['test_precision'].mean():.3f} ± {results['test_precision'].std():.3f}")
    print(f"  CV Recall    : {results['test_recall'].mean():.3f} ± {results['test_recall'].std():.3f}")
    print(f"  CV F1        : {results['test_f1'].mean():.3f} ± {results['test_f1'].std():.3f}")
    print(f"{'='*45}")
    print("\n⚠️  High std deviation = model is unstable (need more data)")

    # Train final model on full dataset
    clf.fit(X, y)
    preds = clf.predict(X)
    print(f"\nFull-dataset training accuracy: {accuracy_score(y, preds):.2f}")
    print(classification_report(y, preds, target_names=["benign", "malware"]))

    # Feature importance
    print("\nTop 10 Feature Importances:")
    importances = sorted(zip(feature_names, clf.feature_importances_),
                        key=lambda x: x[1], reverse=True)[:10]
    for name, imp in importances:
        bar = "█" * int(imp * 50)
        print(f"  {name:<25} {imp:.3f} {bar}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "feature_names": feature_names}, f)
    print(f"\nModel saved: {MODEL_PATH}")
if __name__ == "__main__":
    train()
