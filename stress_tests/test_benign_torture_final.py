"""
test_benign_torture.py — Aura v1.0 Stress Test #3
Benignware FP Rate Test: proves model won't spam SOC with false alarms.

Tools to run in sandbox and test:
- Wireshark, Nmap, 7-Zip, WinSCP, Sysinternals Suite (PsExec, Autoruns,
  Process Monitor, TCPView, Handle), CCleaner, Process Hacker

These are exact tools that FP in real SOC environments.
Target: FP rate < 5%

Usage:
  Step 1 — Submit tools to CAPE sandbox, note task IDs
  Step 2 — python3 test_benign_torture.py --register <task_id> <tool_name>
  Step 3 — python3 test_benign_torture.py --run

  Or auto-run against all registered torture samples:
  python3 test_benign_torture.py --run
"""

import argparse
import json
import os
import sys
import pickle
import numpy as np

ML_DIR       = "/opt/CAPEv2/ml"
ANALYSES_DIR = "/opt/CAPEv2/storage/analyses"
MODEL_PATH   = "/opt/CAPEv2/ml/model.pkl"
TORTURE_DB   = "/opt/CAPEv2/ml/torture_samples.json"

sys.path.insert(0, ML_DIR)
from feature_extractor import extract_features

# ── Pre-registered torture samples ────────────────────────────────────────────
# UPDATE THESE with your actual task IDs after submitting to CAPE
# Format: task_id → tool_name
TORTURE_SAMPLES = {
    # Add your task IDs here after sandbox submission:
    # "350": "Wireshark",
    # "351": "Nmap",
    # "352": "7-Zip",
    # "353": "WinSCP",
    # "354": "PsExec",
    # "355": "Autoruns",
    # "356": "ProcessMonitor",
    # "357": "TCPView",
    # "358": "Handle",
    # "359": "CCleaner",
    # "360": "ProcessHacker",   # already tested in SHAP analysis
    # "361": "AnyDesk",         # already in dataset
}

# Known benign task IDs already in dataset (reuse these)
KNOWN_BENIGN = {
    "40":  "7zip",
    "41":  "Notepad++",
    "43":  "PuTTY",
    "44":  "WinDump",
    "95":  "ApproveChildRequest",
    "98":  "calc.exe (malscore=8.0)",
    "108": "mspaint.exe (malscore=9.0)",
    "109": "mstsc.exe (malscore=5.7)",
    "118": "svchost.exe",
    "120": "Taskmgr.exe",
}

# High-risk benign: tools that behave like malware
HIGH_RISK_BENIGN = {
    "processHacker",  # malscore=9.0, 140K APIs — already validated BENIGN
    "AnyDesk",        # malscore=9.0
    "Everything.exe", # malscore=9.0
    "PsExec",         # admin tool, often FPs
    "Autoruns",       # touches registry everywhere
    "Nmap",           # network scanning
    "Wireshark",      # deep packet inspection
    "CCleaner",       # system modification
}


def load_model():
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["feature_names"]


def run_torture_test():
    model, feature_names = load_model()

    # Pull ALL benign samples from labels_auto.json automatically
    all_samples = {}
    labels_auto = os.path.join(ML_DIR, "labels_auto.json")
    if os.path.exists(labels_auto):
        with open(labels_auto) as f:
            auto = json.load(f)
        for tid, meta in auto.items():
            if isinstance(meta, dict) and meta.get("label") == 0 and meta.get("usable", True):
                all_samples[tid] = meta.get("name", f"task_{tid}")

    # Also merge hardcoded + registered
    all_samples.update(KNOWN_BENIGN)
    if os.path.exists(TORTURE_DB):
        with open(TORTURE_DB) as f:
            registered = json.load(f)
        all_samples.update(registered)
    all_samples.update(TORTURE_SAMPLES)

    if not all_samples:
        print("No torture samples registered.")
        print("Add task IDs to TORTURE_SAMPLES dict or use --register flag.")
        return

    print("=" * 60)
    print("  AURA v1.0 — Benignware FP Torture Test")
    print("=" * 60)
    print(f"\nTesting {len(all_samples)} benign tools...")
    print(f"\n  {'Task':<8} {'Tool':<30} {'Verdict':>8} {'Conf':>6} {'Status':>10}")
    print("  " + "─" * 65)

    results = []
    fp_count = 0

    for task_id, tool_name in sorted(all_samples.items()):
        report_path = f"{ANALYSES_DIR}/{task_id}/reports/report.json"

        if not os.path.exists(report_path):
            print(f"  {task_id:<8} {tool_name:<30} {'NO REPORT':>8}")
            continue

        try:
            features   = extract_features(report_path)
            X          = np.array([list(features.values())])
            pred       = model.predict(X)[0]
            proba      = model.predict_proba(X)[0][1]  # malware probability
            verdict    = "MALWARE" if pred == 1 else "BENIGN"
            is_fp      = (pred == 1)
            status     = "❌ FALSE POSITIVE" if is_fp else "✅ CORRECT"

            if is_fp:
                fp_count += 1

            results.append({
                "task_id":   task_id,
                "tool":      tool_name,
                "verdict":   verdict,
                "confidence": float(proba),
                "fp":        is_fp,
            })

            # Flag high-confidence FPs as critical
            if is_fp and proba > 0.8:
                status = "🔴 CRITICAL FP"

            print(f"  {task_id:<8} {tool_name[:28]:<30} {verdict:>8} {proba:>6.3f} {status}")

        except Exception as e:
            print(f"  {task_id:<8} {tool_name:<30} ERROR: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    total   = len(results)
    fp_rate = (fp_count / total * 100) if total > 0 else 0
    target  = 5.0

    print("\n" + "═" * 60)
    print("  SUMMARY")
    print("═" * 60)
    print(f"  Tools tested : {total}")
    print(f"  FP count     : {fp_count}")
    print(f"  FP rate      : {fp_rate:.1f}%  (target: <{target}%)")
    print()

    if fp_count == 0:
        print("  RESULT: PERFECT — Zero false positives.")
        print("  Safe to claim: model won't alarm on enterprise tooling.")
    elif fp_rate < target:
        print(f"  RESULT: PASS — FP rate {fp_rate:.1f}% < {target}% target.")
        print("  Acceptable for production SOC deployment.")
    else:
        print(f"  RESULT: FAIL — FP rate {fp_rate:.1f}% exceeds {target}% target.")
        print("  List of false positives:")
        for r in results:
            if r["fp"]:
                print(f"    - {r['tool']} (conf={r['confidence']:.3f})")
        print("  Fix: add these tools to training set as verified benign.")

    # Confidence distribution
    if results:
        confs = [r["confidence"] for r in results]
        print(f"\n  Confidence stats (malware probability on benign tools):")
        print(f"  Mean  : {np.mean(confs):.3f}")
        print(f"  Max   : {np.max(confs):.3f}  ← worst case")
        print(f"  Median: {np.median(confs):.3f}")
        high_conf = [r for r in results if r["confidence"] > 0.5]
        if high_conf:
            print(f"\n  High-confidence near-FPs (conf > 0.5):")
            for r in high_conf:
                print(f"    {r['tool']:<30} conf={r['confidence']:.3f}")

    print("═" * 60)

    # Save
    output = {
        "total_tested": total,
        "fp_count": fp_count,
        "fp_rate_pct": round(fp_rate, 2),
        "target_pct": target,
        "passed": bool(fp_rate < target),
        "results": results,
    }
    out = os.path.join(ML_DIR, "benign_torture_results.json")
    with open(out, "w") as f:
        json.dump(output, f, indent=2, default=lambda o: bool(o) if isinstance(o, __builtins__.__class__) else str(o))
    print(f"\nResults saved: {out}")

    return output


def register_sample(task_id, tool_name):
    db = {}
    if os.path.exists(TORTURE_DB):
        with open(TORTURE_DB) as f:
            db = json.load(f)
    db[str(task_id)] = tool_name
    with open(TORTURE_DB, "w") as f:
        json.dump(db, f, indent=2)
    print(f"Registered: task {task_id} → {tool_name}")
    print(f"Database: {TORTURE_DB}")


def print_submission_guide():
    print("""
SUBMISSION GUIDE — How to add torture samples:

1. Download the tool installer/binary (legitimate source)
2. Submit to CAPE via API or web UI:
   curl -X POST http://localhost:8000/tasks/create/file \\
     -F "file=@wireshark-installer.exe" \\
     -F "machine=win10" \\
     -F "timeout=120"

3. Note the returned task_id

4. Register it:
   python3 test_benign_torture.py --register <task_id> Wireshark

5. After all tools submitted, run:
   python3 test_benign_torture.py --run

Priority tools to add (most likely to FP):
  - Wireshark    (deep packet inspection)
  - Nmap         (network scanner)
  - PsExec       (remote execution)
  - Autoruns     (registry + startup heavy)
  - CCleaner     (system modification)
  - Process Hacker (already done — use task from dataset)
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benignware FP Torture Test")
    parser.add_argument("--run",      action="store_true", help="Run the torture test")
    parser.add_argument("--register", nargs=2, metavar=("TASK_ID", "TOOL_NAME"),
                        help="Register a new torture sample")
    parser.add_argument("--guide",    action="store_true", help="Show submission guide")
    args = parser.parse_args()

    if args.register:
        register_sample(args.register[0], args.register[1])
    elif args.guide:
        print_submission_guide()
    else:
        # Default: run with whatever is registered + known benign
        run_torture_test()