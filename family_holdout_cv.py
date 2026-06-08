"""
family_holdout_cv.py — Aura v1.0
Family-Held-Out Cross Validation using GroupKFold.

Proves the model generalizes to UNSEEN malware families,
not just memorizing known ones.

Run: python3 family_holdout_cv.py
"""

import json
import re
import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, StratifiedKFold, cross_validate
from sklearn.metrics import (
    make_scorer, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# ── Paths ─────────────────────────────────────────────────────────────────────
ANALYSES_DIR  = "/opt/CAPEv2/storage/analyses"
LABELS_AUTO   = "/opt/CAPEv2/ml/labels_auto.json"
ML_DIR        = "/opt/CAPEv2/ml"

sys.path.insert(0, ML_DIR)
from feature_extractor import extract_features

# ── Hardcoded family map (task_id → family name) ──────────────────────────────
# Benign samples all get family="benign" — they are one group.
# Malware samples get their actual family name.
HARDCODED_FAMILIES = {
    "12":  "benign",
    "15":  "WannaCry",
    "18":  "WannaCry",
    "19":  "Kelihos",
    "20":  "NjRAT",
    "21":  "Raccoon",
    "22":  "Cerber",
    "23":  "CryptoWall",
    "24":  "Locky",
    "25":  "Petya",
    "27":  "Shamoon",
    "29":  "Asprox",
    "30":  "Bladabindi",
    "31":  "Kovter",
    "32":  "AgentTesla",
    "33":  "Carberp",
    "34":  "Cridex",
    "36":  "Emotet",
    "38":  "zeus",
    "39":  "zeus",
    "40":  "benign",
    "41":  "benign",
    "43":  "benign",
    "44":  "benign",
    "95":  "benign", "96":  "benign", "97":  "benign", "98":  "benign",
    "99":  "benign", "100": "benign", "101": "benign", "102": "benign",
    "103": "benign", "104": "benign", "105": "benign", "106": "benign",
    "107": "benign", "108": "benign", "109": "benign", "110": "benign",
    "111": "benign", "112": "benign", "113": "benign", "114": "benign",
    "115": "benign", "116": "benign", "117": "benign", "118": "benign",
    "119": "benign", "120": "benign", "121": "benign",
    "122": "CryptoLocker",
    "124": "CryptoLocker",
    "127": "Loadmoney",
}


def extract_family_from_name(name: str) -> str:
    """
    Normalize to true malware family, stripping:
    - known prefixes: trojan, stealer, ransomware, downloader, banking, holdout
    - hex hashes: any segment that is 8+ hex chars
    - file extensions
    - date suffixes like 10Sep2013

    Examples:
      trojan_nanocore_0caacc324e   → nanocore
      stealer_AgentTesla_4bda75ee  → agenttesla
      ransomware_GandCrab_0400e0f6 → gandcrab
      WannaCry                     → wannacry
      CryptoLocker_10Sep2013       → cryptolocker
      asyncrat_5722bae97d          → asyncrat
    """
    PREFIXES = {"trojan", "stealer", "ransomware", "downloader",
                "banking", "holdout", "win32", "win64", "worm",
                "backdoor", "adware", "dropper", "generic", "spyware"}

    # Strip extensions
    for ext in [".bin", ".exe", ".dll", ".zip"]:
        if name.lower().endswith(ext):
            name = name[:-len(ext)]

    # Split on _ or -
    parts = re.split(r"[_\-]", name)

    # Drop: pure hex hashes (8+ hex chars), known prefixes, date strings
    clean = []
    for p in parts:
        pl = p.lower()
        if re.fullmatch(r"[0-9a-f]{8,}", pl):   continue  # hash
        if pl in PREFIXES:                         continue  # prefix
        if re.fullmatch(r"\d{1,2}[a-z]{3}\d{4}", pl, re.I): continue  # date e.g. 10Sep2013
        if re.fullmatch(r"v\d+", pl):            continue  # version tag v0, v2
        if len(pl) < 2:                            continue  # single char noise
        clean.append(pl)

    result = clean[0].lower() if clean else name.lower()
    # Apply canonical alias map
    ALIASES = {
        "zeusbanking": "zeus", "zeusbankingversion": "zeus", "zeusgameover": "zeus", "zeus": "zeus",
        "trojan.kovter": "kovter", "ransomware.cerber": "cerber",
        "ransomware.cryptowall": "cryptowall", "ransomware.locky": "locky",
        "win32.cridex": "cridex", "win32.agenttesla": "agenttesla",
        "win32.carberp": "carberp", "win32.darktequila": "darktequila",
        "win32.hupigon": "hupigon", "win32.infostealer.dexter": "dexter",
        "win32.keypass": "keypass", "win32.mydoom.a": "mydoom",
        "w32.mydoom.a": "mydoom", "win32.sofacy.a": "sofacy",
        "win32.vobfus": "vobfus", "trojan.asprox": "asprox",
        "trojan.nsis.win32": "nsis", "trojan.sinowal": "sinowal",
        "ransomware.hive": "hive", "ransomware.matsnu": "matsnu",
        "ransomware.petrwrap": "petrwrap", "ransomware.radamant": "radamant",
        "ransomware.satana": "satana", "ransomware.teslacrypt": "teslacrypt",
        "ransomware.xdata": "xdata", "keylogger.ardamax": "ardamax",
        "raccoon.stealer.v2": "raccoon", "waski.upatre": "upatre",
        "njrat-v0": "njrat", "cryptolocker_10sep2013": "cryptolocker",
        "cryptolocker_20nov2013": "cryptolocker", "cryptolocker_22jan2014": "cryptolocker",
        "nitlove": "nitol",
    }
    return ALIASES.get(result, result)


def load_dataset():
    X, y, families, names = [], [], [], []
    feature_names = None
    skipped = 0

    # ── Merge hardcoded + auto labels ─────────────────────────────────────────
    merged = {}  # task_id → {label, family}

    for tid, family in HARDCODED_FAMILIES.items():
        label = 0 if family == "benign" else 1
        merged[tid] = {"label": label, "family": family.lower()}

    if os.path.exists(LABELS_AUTO):
        with open(LABELS_AUTO) as f:
            auto = json.load(f)
        for tid, meta in auto.items():
            if isinstance(meta, dict):
                if not meta.get("usable", True):
                    continue
                label  = meta["label"]
                name   = meta.get("name", f"task_{tid}")
                family = extract_family_from_name(name) if label == 1 else "benign"
            else:
                label  = int(meta)
                family = f"auto_{tid}" if label == 1 else "benign"
            merged[str(tid)] = {"label": label, "family": family}
        print(f"Auto labels loaded: {len(auto)} entries")

    print(f"Total merged: {len(merged)} labels")

    # ── Extract features ───────────────────────────────────────────────────────
    for tid, meta in merged.items():
        report_path = f"{ANALYSES_DIR}/{tid}/reports/report.json"
        if not os.path.exists(report_path):
            skipped += 1
            continue
        try:
            features = extract_features(report_path)
            if feature_names is None:
                feature_names = list(features.keys())
            X.append(list(features.values()))
            y.append(meta["label"])
            families.append(meta["family"])
            names.append(f"task_{tid}")
        except Exception as e:
            print(f"  Error task {tid}: {e}")
            skipped += 1

    print(f"Skipped (no report / error): {skipped}")
    return (np.array(X), np.array(y),
            np.array(families), np.array(names), feature_names)


def print_separator(char="─", width=55):
    print(char * width)


def run_stratified_cv(X, y):
    """Baseline: standard StratifiedKFold (current method)."""
    print("\n[BASELINE] StratifiedKFold 5-fold")
    print_separator()

    clf = RandomForestClassifier(n_estimators=100, random_state=42,
                                 class_weight="balanced")
    cv  = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = {
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score,    zero_division=0),
        "f1":        make_scorer(f1_score,        zero_division=0),
    }
    results = cross_validate(clf, X, y, cv=cv, scoring=scoring)

    f1s = results["test_f1"]
    print(f"  CV Precision : {results['test_precision'].mean():.3f} ± {results['test_precision'].std():.3f}")
    print(f"  CV Recall    : {results['test_recall'].mean():.3f}    ± {results['test_recall'].std():.3f}")
    print(f"  CV F1        : {f1s.mean():.3f} ± {f1s.std():.3f}")
    print(f"  Per-fold F1  : {[f'{v:.3f}' for v in f1s]}")
    return f1s.mean(), f1s.std()


def run_family_holdout_cv(X, y, families):
    """
    GroupKFold: each fold holds out ALL samples from specific families.
    Tests whether model detects families it has NEVER seen during training.
    """
    print("\n[STRESS TEST] Family-Held-Out GroupKFold")
    print_separator()

    unique_families = np.unique(families)
    malware_families = [f for f in unique_families if f != "benign"]
    print(f"  Unique families  : {len(unique_families)}")
    print(f"  Malware families : {len(malware_families)}")
    print(f"  Family list      : {sorted(malware_families)}\n")

    # GroupKFold: groups = families
    # Benign samples are always split across folds (group="benign" treated as one group)
    # This means benign can appear in both train and test — realistic
    n_splits = min(5, len(malware_families))

    # Custom splitter: GroupKFold on malware only, then add ALL benign to every test fold
    malware_idx = np.where(y == 1)[0]
    benign_idx  = np.where(y == 0)[0]
    mal_families = families[malware_idx]

    gkf = GroupKFold(n_splits=n_splits)

    fold_results = []
    held_out_log = []

    for fold, (mal_train_rel, mal_test_rel) in enumerate(
            gkf.split(X[malware_idx], y[malware_idx], groups=mal_families)):

        # Absolute indices
        mal_train_idx = malware_idx[mal_train_rel]
        mal_test_idx  = malware_idx[mal_test_rel]

        # Split benign 80/20 by index order (stable, no leakage)
        ben_cut       = int(len(benign_idx) * 0.8)
        ben_train_idx = benign_idx[:ben_cut]
        ben_test_idx  = benign_idx[ben_cut:]

        train_idx = np.concatenate([mal_train_idx, ben_train_idx])
        test_idx  = np.concatenate([mal_test_idx,  ben_test_idx])

        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        held_families = np.unique(families[mal_test_idx])
        held_malware  = list(held_families)

        clf = RandomForestClassifier(n_estimators=100, random_state=42,
                                     class_weight="balanced")
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)

        p = precision_score(y_test, preds, zero_division=0)
        r = recall_score(y_test, preds, zero_division=0)
        f = f1_score(y_test, preds, zero_division=0)
        cm = confusion_matrix(y_test, preds, labels=[0, 1])

        tn, fp, fn, tp = cm.ravel() if cm.shape == (2,2) else (0,0,0,0)

        fold_results.append({"precision": p, "recall": r, "f1": f,
                              "tp": tp, "fp": fp, "fn": fn, "tn": tn})
        held_out_log.append(held_malware)

        print(f"  Fold {fold+1} | Held-out families: {held_malware}")
        print(f"         P={p:.3f}  R={r:.3f}  F1={f:.3f}  "
              f"TP={tp} FP={fp} FN={fn} TN={tn}")

    # ── Aggregate ─────────────────────────────────────────────────────────────
    f1s  = [r["f1"]        for r in fold_results]
    recs = [r["recall"]    for r in fold_results]
    pres = [r["precision"] for r in fold_results]
    fns  = [r["fn"]        for r in fold_results]

    mean_f1  = np.mean(f1s)
    std_f1   = np.std(f1s)
    mean_rec = np.mean(recs)
    mean_pre = np.mean(pres)
    total_fn  = sum(fns)

    print_separator()
    print(f"  CV Precision : {mean_pre:.3f} ± {np.std(pres):.3f}")
    print(f"  CV Recall    : {mean_rec:.3f} ± {np.std(recs):.3f}")
    print(f"  CV F1        : {mean_f1:.3f} ± {std_f1:.3f}")
    print(f"  Per-fold F1  : {[f'{v:.3f}' for v in f1s]}")
    print(f"  Total FN     : {total_fn}  (malware missed across all folds)")

    return mean_f1, std_f1, fold_results, held_out_log


def per_family_analysis(X, y, families, feature_names):
    """
    Train on ALL data, then evaluate per-family.
    Shows which families the model struggles with.
    """
    print("\n[PER-FAMILY] Train-all, evaluate per-family")
    print_separator()

    clf = RandomForestClassifier(n_estimators=100, random_state=42,
                                 class_weight="balanced")
    clf.fit(X, y)

    unique_families = [f for f in np.unique(families) if f != "benign"]
    results = []

    for fam in sorted(unique_families):
        idx   = np.where(families == fam)[0]
        preds = clf.predict(X[idx])
        true  = y[idx]
        f1    = f1_score(true, preds, zero_division=0)
        rec   = recall_score(true, preds, zero_division=0)
        n     = len(idx)
        missed = int((true == 1).sum() - (preds[true == 1] == 1).sum())
        results.append((fam, n, f1, rec, missed))

    # Sort by recall (worst first)
    results.sort(key=lambda x: x[3])

    print(f"  {'Family':<25} {'N':>4}  {'F1':>6}  {'Recall':>7}  {'Missed':>7}")
    print_separator("─", 55)
    for fam, n, f1, rec, missed in results:
        flag = " ← WEAK" if rec < 0.8 else ""
        print(f"  {fam:<25} {n:>4}  {f1:>6.3f}  {rec:>7.3f}  {missed:>7}{flag}")

    return results


def print_verdict(baseline_f1, holdout_f1, baseline_std, holdout_std):
    print("\n" + "═" * 55)
    print("  VERDICT")
    print("═" * 55)
    print(f"  Stratified CV F1  (baseline) : {baseline_f1:.3f} ± {baseline_std:.3f}")
    print(f"  Family Holdout F1 (stress)   : {holdout_f1:.3f} ± {holdout_std:.3f}")
    drop = baseline_f1 - holdout_f1
    print(f"  Score drop                   : {drop:.3f}")
    print()

    if drop < 0.05:
        print("  RESULT: STRONG generalization.")
        print("  Model detects unseen families reliably.")
        print("  Safe to claim family-level generalization.")
    elif drop < 0.12:
        print("  RESULT: ACCEPTABLE generalization.")
        print("  Some family-specific memorization exists.")
        print("  Report both numbers honestly.")
    else:
        print("  RESULT: WEAK generalization.")
        print("  Model memorizes known families.")
        print("  Do NOT claim production-level detection.")
        print("  Fix: add more diverse families, tune features.")

    print("═" * 55)


def main():
    print("=" * 55)
    print("  AURA v1.0 — Family-Held-Out Validation")
    print("=" * 55)

    X, y, families, names, feature_names = load_dataset()
    print(f"\nDataset: {len(X)} samples | "
          f"{sum(y)} malware | {len(y)-sum(y)} benign")

    if len(X) < 10:
        print("Not enough samples.")
        return

    # 1. Baseline (current method)
    baseline_f1, baseline_std = run_stratified_cv(X, y)

    # 2. Family holdout (stress test)
    holdout_f1, holdout_std, fold_results, held_log = \
        run_family_holdout_cv(X, y, families)

    # 3. Per-family breakdown
    per_family_analysis(X, y, families, feature_names)

    # 4. Final verdict
    print_verdict(baseline_f1, holdout_f1, baseline_std, holdout_std)

    # 5. Save results
    output = {
        "baseline_stratified": {"f1": round(baseline_f1, 4), "std": round(baseline_std, 4)},
        "family_holdout":      {"f1": round(holdout_f1,  4), "std": round(holdout_std,  4)},
        "drop":                round(baseline_f1 - holdout_f1, 4),
        "folds": [
            {
                "held_families": held_log[i],
                "f1": round(fold_results[i]["f1"], 4),
                "recall": round(fold_results[i]["recall"], 4),
                "precision": round(fold_results[i]["precision"], 4),
                "fn": fold_results[i]["fn"],
                "fp": fold_results[i]["fp"],
            }
            for i in range(len(fold_results))
        ]
    }

    class NpEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, np.integer): return int(obj)
            if isinstance(obj, np.floating): return float(obj)
            if isinstance(obj, np.ndarray): return obj.tolist()
            return super().default(obj)

    out_path = os.path.join(ML_DIR, "family_holdout_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, cls=NpEncoder)
    print(f"\nResults saved: {out_path}")


if __name__ == "__main__":
    main()