# AI Malware Behavior Analyzer

> **Full-Stack Detection Engineering Pipeline** combining CAPEv2 signature-based sandboxing with ML-based behavioral classification through a custom Out-of-Band VMware control layer.

## Architecture
```
Windows 10 Host (VMware Workstation)
├── OOB Management Layer — vmrun_bridge.py (192.168.75.1:9090)
│   Exposes /vm/start, /vm/stop, /snapshot/revert via vmrun.exe
├── Ubuntu 24.04 VM (192.168.75.133)
│   ├── CAPEv2 Sandbox → localhost:8000
│   ├── VMwareBridge Machinery (custom module)
│   └── ML Pipeline → Flask API :5000
└── Flare VM (192.168.75.131 — Host-Only, NO internet)
    ├── CAPE Agent 0.20
    ├── Windows Defender DISABLED
    └── Snapshot: flare-clean
```

## Why VMware over KVM

CAPEv2 uses libvirt/KVM by default. Running Ubuntu inside VMware makes nested KVM unstable. Instead of fighting nested virtualization, this project builds a custom Out-of-Band control layer — a Flask server on the Windows host that exposes vmrun.exe as HTTP endpoints, paired with a custom VMwareBridge machinery module replacing libvirt entirely.

> VMware was chosen over QEMU/KVM to provide more realistic hardware fingerprints and reduce basic sandbox detection indicators.

## Results

| Sample | Verdict | Confidence | Malscore | API Calls |
|--------|---------|------------|----------|-----------|
| wannacry.exe | MALWARE | 78% | 10.0 | 94,958 |
| eicar.exe | BENIGN | 74% | 0.0 | 0 |

## CAPE Signatures vs ML Classification

| Method | Strength | Limitation |
|--------|----------|-----------|
| CAPE Signatures | Precise family attribution | Fails on unknown variants |
| ML Classifier | Generalizes across families | Requires training data |

Combined: CAPE signatures feed into ML features — rule-based and statistical reasoning reinforce each other.

## Security Containment

Flare VM uses VMware Host-Only networking. No internet access. WannaCry's SMB scanning (EternalBlue) is contained within the isolated subnet. C2 callbacks fail at DNS resolution.

## API Usage
```bash
# Start API
python ml/app.py

# Predict
curl -X POST http://localhost:5000/predict \
  -F "report=@/path/to/report.json"

# CLI
python ml/predict.py /path/to/report.json
```

## Limitations

- Small dataset (2 samples currently — scaling to 50+)
- Global feature counts, not temporal API sequences
- VMware artifacts detectable by sophisticated malware
- No SHAP explainability yet

## Future Work

- Scale to 300+ samples via MalwareBazaar
- Temporal API sequence modeling (n-grams)
- MITRE ATT&CK TTP mapping per prediction
- SHAP explainability in API response

## Stack

| Component | Technology |
|-----------|-----------|
| Sandbox | CAPEv2 2.5 on Ubuntu 24.04 |
| Analysis VM | Flare VM (Windows 10) |
| OOB Control | Flask + vmrun.exe bridge |
| ML | scikit-learn RandomForest |
| API | Flask REST |

## Author

**Vishva Teja Chikoti** — M.S. Cybersecurity & Networks, University of New Haven 2026
GitHub: [ckvishwa](https://github.com/ckvishwa)
