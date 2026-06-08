#!/usr/bin/env python3
"""
shap_explain.py
===============
SHAP explainability for Aura malware classifier.

Generates:
  1. Global feature importance (beeswarm plot)
  2. Per-prediction explanation (waterfall plot)
  3. JSON explanation for Flask API integration

Usage:
  sudo python3 ml/shap_explain.py                          # explain all training samples
  sudo python3 ml/shap_explain.py --report path/to/report.json  # explain single sample
  sudo python3 ml/shap_explain.py --task 294               # explain by CAPE task ID
"""

import os
import sys
import json
import pickle
import argparse
import numpy as np

CAPE_DIR   = "/opt/CAPEv2"
ML_DIR     = f"{CAPE_DIR}/ml"
MODEL_PATH = f"{ML_DIR}/model.pkl"
PLOTS_DIR  = f"{ML_DIR}/shap_plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

# ── Load model ────────────────────────────────────────────────────────────────
def load_model():
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)
    return data["model"], data["feature_names"]

# ── Load dataset ──────────────────────────────────────────────────────────────
def load_dataset():
    """Load all labeled samples into X, y arrays."""
    sys.path.insert(0, ML_DIR)
    from feature_extractor import extract_features

    ANALYSES_DIR = f"{CAPE_DIR}/storage/analyses"
    LABELS_PATH  = f"{ML_DIR}/labels_auto.json"

    labels_auto = json.load(open(LABELS_PATH)) if os.path.exists(LABELS_PATH) else {}

    # Hardcoded labels
    LABELS = {
        "12": 0, "15": 1, "18": 1, "19": 1, "20": 1,
        "21": 1, "22": 1, "23": 1, "24": 1, "25": 1,
        "27": 1, "29": 1, "30": 1, "31": 1, "32": 1,
        "33": 1, "34": 1, "36": 1, "38": 1, "39": 1,
    }

    merged = {}
    for tid, lbl in LABELS.items():
        merged[str(tid)] = lbl
    for tid, meta in labels_auto.items():
        if isinstance(meta, dict):
            if not meta.get("usable", True):
                continue
            merged[str(tid)] = meta["label"]
        else:
            merged[str(tid)] = int(meta)

    X, y, names, task_ids = [], [], [], []
    feature_names = None

    for task_id, label in merged.items():
        report = f"{ANALYSES_DIR}/{task_id}/reports/report.json"
        if not os.path.exists(report):
            continue
        try:
            feats = extract_features(report)
            if feature_names is None:
                feature_names = list(feats.keys())
            X.append(list(feats.values()))
            y.append(label)
            # Get sample name
            r = json.load(open(report))
            name = r.get("target", {}).get("file", {}).get("name", f"task_{task_id}")
            names.append(name)
            task_ids.append(task_id)
        except Exception as e:
            print(f"  [!] Error task {task_id}: {e}")

    return np.array(X), np.array(y), feature_names, names, task_ids

# ── Global SHAP Analysis ──────────────────────────────────────────────────────
def global_shap(clf, X, feature_names, names):
    """Generate global SHAP plots — feature importance across all samples."""
    import shap
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    print("[*] Computing SHAP values for all samples...")
    explainer   = shap.TreeExplainer(clf)
    shap_values = explainer.shap_values(X)

    # Handle both list format and 3D array format from different SHAP versions
    # 3D array shape: (n_samples, n_features, n_classes) -> use class 1 (malware)
    if isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        sv = shap_values[:, :, 1]
    elif isinstance(shap_values, list):
        sv = shap_values[1]
    else:
        sv = shap_values

    print(f"[*] SHAP values shape: {sv.shape}")

    # ── 1. Beeswarm plot ──────────────────────────────────────────────────────
    print("[*] Generating beeswarm plot...")
    plt.figure(figsize=(12, 9))
    plt.style.use('dark_background')
    shap.summary_plot(
        sv, X,
        feature_names=feature_names,
        show=False,
        plot_size=(12, 9),
        color_bar_label="Feature Value"
    )
    plt.title("SHAP Feature Impact — Malware Classification\n"
              "Red = high feature value pushes toward MALWARE",
              fontsize=12, pad=12)
    plt.tight_layout()
    out = f"{PLOTS_DIR}/shap_beeswarm.png"
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#0D1117')
    plt.close()
    print(f"[+] Saved: {out}")

    # ── 2. Bar plot — mean absolute SHAP ─────────────────────────────────────
    print("[*] Generating bar importance plot...")
    mean_abs = np.abs(sv).mean(axis=0)
    sorted_idx = np.argsort(mean_abs)[::-1][:15]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#0D1117')
    ax.set_facecolor('#161B22')

    colors = ['#00FF88' if mean_abs[i] > 0.05 else '#00D4FF'
              for i in sorted_idx]
    bars = ax.barh(
        [feature_names[i] for i in sorted_idx][::-1],
        [mean_abs[i] for i in sorted_idx][::-1],
        color=colors[::-1], edgecolor='#30363D', linewidth=0.5
    )

    for bar, val in zip(bars, [mean_abs[i] for i in sorted_idx][::-1]):
        ax.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height()/2,
                f'{val:.4f}', va='center', fontsize=8, color='#E6EDF3')

    ax.set_xlabel('Mean |SHAP Value|', color='#8B949E')
    ax.set_title('Top 15 Features by Mean SHAP Impact',
                 color='#E6EDF3', fontsize=12, fontweight='bold')
    ax.tick_params(colors='#8B949E')
    ax.spines['bottom'].set_color('#30363D')
    ax.spines['left'].set_color('#30363D')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='x', alpha=0.3, color='#21262D')

    plt.tight_layout()
    out = f"{PLOTS_DIR}/shap_bar.png"
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#0D1117')
    plt.close()
    print(f"[+] Saved: {out}")

    # ── 3. Print top features ─────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  GLOBAL SHAP FEATURE IMPORTANCE (Top 15)")
    print(f"{'='*55}")
    for i in sorted_idx[:15]:
        bar = '█' * int(mean_abs[i] * 200)
        print(f"  {feature_names[i]:<30} {mean_abs[i]:.4f}  {bar}")
    print(f"{'='*55}\n")

    return explainer, shap_values

# ── Per-Sample SHAP Explanation ───────────────────────────────────────────────
def explain_sample(clf, explainer, feature_names, features, sample_name="sample"):
    """
    Generate SHAP waterfall explanation for a single sample.
    Returns dict with top contributing features and verdict reasoning.
    """
    import shap
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    x = np.array([features])

    # Compute SHAP values for this sample
    raw_sv = explainer.shap_values(x)
    if isinstance(raw_sv, np.ndarray) and raw_sv.ndim == 3:
        sv_malware = raw_sv[0, :, 1]
        base_val   = float(explainer.expected_value[1]) if hasattr(explainer.expected_value, '__len__') else float(explainer.expected_value)
    elif isinstance(raw_sv, list):
        sv_malware = np.array(raw_sv[1][0])
        base_val   = float(explainer.expected_value[1]) if isinstance(explainer.expected_value, list) else float(explainer.expected_value)
    else:
        sv_malware = np.array(raw_sv[0])
        base_val   = float(explainer.expected_value)

    # Prediction
    pred       = clf.predict(x)[0]
    prob       = clf.predict_proba(x)[0]
    verdict    = "MALWARE" if pred == 1 else "BENIGN"
    confidence = round(float(max(prob)) * 100, 1)

    # Top positive contributors (push toward malware)
    pos_idx = np.argsort(sv_malware)[::-1][:8]
    # Top negative contributors (push toward benign)
    neg_idx = np.argsort(sv_malware)[:8]

    # ── Waterfall plot ────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor('#0D1117')
    ax.set_facecolor('#161B22')

    # Show top 10 by absolute SHAP value
    top_idx  = np.argsort(np.abs(sv_malware))[::-1][:10]
    top_vals = [(feature_names[i], sv_malware[i], features[i]) for i in top_idx]
    top_vals.sort(key=lambda x: x[1])  # Sort by SHAP value

    labels = [f"{name}\n(val={val:.2f})" for name, shap, val in top_vals]
    shaps  = [shap for _, shap, _ in top_vals]
    colors = ['#FF4444' if s > 0 else '#00D4FF' for s in shaps]

    bars = ax.barh(labels, shaps, color=colors, edgecolor='#30363D', linewidth=0.5)
    ax.axvline(x=0, color='#8B949E', linewidth=1)

    for bar, val in zip(bars, shaps):
        x_pos = bar.get_width() + 0.002 if val >= 0 else bar.get_width() - 0.002
        ha    = 'left' if val >= 0 else 'right'
        ax.text(x_pos, bar.get_y() + bar.get_height()/2,
                f'{val:+.4f}', va='center', fontsize=8,
                color='#FF4444' if val > 0 else '#00D4FF', ha=ha)

    verdict_color = '#FF4444' if verdict == 'MALWARE' else '#00FF88'
    ax.set_title(
        f"SHAP Explanation — {sample_name}\n"
        f"Verdict: {verdict} ({confidence}% confidence)\n"
        f"Red = pushes toward MALWARE | Blue = pushes toward BENIGN",
        color='#E6EDF3', fontsize=10, fontweight='bold'
    )
    ax.set_xlabel('SHAP Value (impact on malware probability)', color='#8B949E')
    ax.tick_params(colors='#8B949E', labelsize=8)
    ax.spines['bottom'].set_color('#30363D')
    ax.spines['left'].set_color('#30363D')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='x', alpha=0.3, color='#21262D')

    plt.tight_layout()
    safe_name = sample_name.replace('.', '_').replace('/', '_')
    out = f"{PLOTS_DIR}/shap_waterfall_{safe_name}.png"
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#0D1117')
    plt.close()
    print(f"[+] Saved: {out}")

    # ── Text explanation ──────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  VERDICT:     {verdict}")
    print(f"  CONFIDENCE:  {confidence}%")
    print(f"  MALWARE P:   {round(prob[1]*100, 1)}%")
    print(f"{'─'*55}")
    print(f"  TOP INDICATORS (SHAP):")

    # Positive contributors
    pos = [(feature_names[i], sv_malware[i], features[i])
           for i in np.argsort(sv_malware)[::-1][:5]
           if sv_malware[i] > 0.001]
    if pos:
        print(f"  → Pushing MALWARE:")
        for name, shap, val in pos:
            print(f"    {name:<28} val={val:<8.2f} shap={shap:+.4f}")

    # Negative contributors
    neg = [(feature_names[i], sv_malware[i], features[i])
           for i in np.argsort(sv_malware)[:5]
           if sv_malware[i] < -0.001]
    if neg:
        print(f"  → Pushing BENIGN:")
        for name, shap, val in neg:
            print(f"    {name:<28} val={val:<8.2f} shap={shap:+.4f}")

    print(f"{'='*55}\n")

    # ── JSON explanation ──────────────────────────────────────────────────────
    explanation = {
        "sample":     sample_name,
        "verdict":    verdict,
        "confidence": confidence,
        "malware_probability": round(float(prob[1]) * 100, 1),
        "shap_base_value": round(float(base_val), 4),
        "top_malware_indicators": [
            {
                "feature":    feature_names[i],
                "value":      round(float(features[i]), 4),
                "shap_impact": round(float(sv_malware[i]), 4),
                "direction":  "malware"
            }
            for i in np.argsort(sv_malware)[::-1][:5]
            if sv_malware[i] > 0.001
        ],
        "top_benign_indicators": [
            {
                "feature":    feature_names[i],
                "value":      round(float(features[i]), 4),
                "shap_impact": round(float(sv_malware[i]), 4),
                "direction":  "benign"
            }
            for i in np.argsort(sv_malware)[:5]
            if sv_malware[i] < -0.001
        ],
    }

    out_json = f"{PLOTS_DIR}/shap_{safe_name}.json"
    with open(out_json, "w") as f:
        json.dump(explanation, f, indent=2)
    print(f"[+] JSON: {out_json}")

    return explanation

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
MITRE_MAP = {
    "has_process_injection":   ("T1055",  "Process Injection"),
    "has_persistence":         ("T1547",  "Boot/Logon Autostart Execution"),
    "has_shadow_deletion":     ("T1490",  "Inhibit System Recovery"),
    "has_credential_access":   ("T1003",  "OS Credential Dumping"),
    "has_sleep_evasion":       ("T1497",  "Virtualization/Sandbox Evasion"),
    "has_keylogger":           ("T1056",  "Input Capture"),
    "has_uac_bypass":          ("T1548",  "Abuse Elevation Control Mechanism"),
    "has_ransomware":          ("T1486",  "Data Encrypted for Impact"),
    "has_antidebug":           ("T1622",  "Debugger Evasion"),
    "has_antisandbox":         ("T1497",  "Virtualization/Sandbox Evasion"),
    "has_network_sig":         ("T1071",  "Application Layer Protocol"),
    "has_dropper":             ("T1105",  "Ingress Tool Transfer"),
    "has_rat":                 ("T1219",  "Remote Access Software"),
    "network_before_files":    ("T1071",  "C2 Check-in Pattern"),
    "suspicious_spawn_chains": ("T1059",  "Command and Scripting Interpreter"),
    "has_stealth":             ("T1036",  "Masquerading"),
    "has_packer":              ("T1027",  "Obfuscated Files or Information"),
    "has_infostealer":         ("T1041",  "Exfiltration Over C2 Channel"),
    "has_banker":              ("T1056",  "Input Capture: Credential API Hooking"),
}

def get_mitre_ttps(features, feature_names, shap_values=None):
    """Map active behavioral features to MITRE ATT&CK T-codes."""
    feat_dict = dict(zip(feature_names, features))
    ttps = []
    for feat, (tcode, tname) in MITRE_MAP.items():
        if feat_dict.get(feat, 0) > 0:
            shap_impact = None
            if shap_values is not None:
                idx = feature_names.index(feat) if feat in feature_names else -1
                if idx >= 0:
                    shap_impact = round(float(np.ravel(shap_values)[idx]), 4)
            ttps.append({
                "tcode":       tcode,
                "tname":       tname,
                "feature":     feat,
                "shap_impact": shap_impact,
            })

    if ttps:
        print(f"\n  MITRE ATT&CK TTPs Detected:")
        for t in ttps:
            shap_str = f" (SHAP: {t['shap_impact']:+.4f})" if t['shap_impact'] else ""
            print(f"    {t['tcode']}  {t['tname']}{shap_str}")

    return ttps

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SHAP Explainability for Aura")
    parser.add_argument("--report", type=str, help="Path to CAPE report.json")
    parser.add_argument("--task",   type=str, help="CAPE task ID")
    parser.add_argument("--global-only", action="store_true",
                        help="Only generate global plots, skip per-sample")
    args = parser.parse_args()

    try:
        import shap
        print(f"[*] SHAP version: {shap.__version__}")
    except ImportError:
        print("[!] SHAP not installed. Run: pip install shap --break-system-packages")
        sys.exit(1)

    sys.path.insert(0, ML_DIR)
    from feature_extractor import extract_features

    print("[*] Loading model...")
    clf, feature_names = load_model()
    print(f"[*] Model loaded — {len(feature_names)} features")

    print("[*] Loading dataset...")
    X, y, feat_names, names, task_ids = load_dataset()
    print(f"[*] Dataset: {len(X)} samples ({sum(y)} malware, {len(y)-sum(y)} benign)")

    # ── Global analysis ───────────────────────────────────────────────────────
    explainer, shap_values = global_shap(clf, X, feat_names, names)

    if args.global_only:
        return

    # ── Per-sample analysis ───────────────────────────────────────────────────
    if args.report:
        report_path = args.report
    elif args.task:
        report_path = f"{CAPE_DIR}/storage/analyses/{args.task}/reports/report.json"
    else:
        # Default: explain WannaCry (task 15) and processhacker (task 294)
        demo_tasks = [
            ("15",  "wannacry.exe"),
            ("294", "processhacker.exe"),
        ]
        for task_id, name in demo_tasks:
            rp = f"{CAPE_DIR}/storage/analyses/{task_id}/reports/report.json"
            if os.path.exists(rp):
                print(f"\n[*] Explaining: {name} (task {task_id})")
                feats = extract_features(rp)
                feat_vals = [feats.get(f, 0) for f in feat_names]
                sv = explainer.shap_values(np.array([feat_vals]))
                sv_malware = sv[1][0] if isinstance(sv, list) else sv[0]
                explain_sample(clf, explainer, feat_names, feat_vals, name)
                get_mitre_ttps(feat_vals, feat_names, sv_malware)
        return

    if not os.path.exists(report_path):
        print(f"[!] Report not found: {report_path}")
        sys.exit(1)

    feats     = extract_features(report_path)
    feat_vals = [feats.get(f, 0) for f in feat_names]
    sv        = explainer.shap_values(np.array([feat_vals]))
    sv_malware = sv[1][0] if isinstance(sv, list) else sv[0]

    name = os.path.basename(report_path).replace("report.json", "") or "sample"
    explain_sample(clf, explainer, feat_names, feat_vals, name)
    get_mitre_ttps(feat_vals, feat_names, sv_malware)

if __name__ == "__main__":
    main()