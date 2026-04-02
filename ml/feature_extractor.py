import json
import os

def extract_features(report_path):
    with open(report_path) as f:
        report = json.load(f)

    features = {}

    # Signatures
    sigs = report.get("signatures", [])
    features["num_signatures"] = len(sigs)
    features["has_antidebug"] = int(any("antidebug" in s.get("name","") for s in sigs))
    features["has_antisandbox"] = int(any("antisandbox" in s.get("name","") for s in sigs))
    features["has_network"] = int(any("network" in s.get("name","") for s in sigs))
    features["has_stealth"] = int(any("stealth" in s.get("name","") for s in sigs))
    features["has_ransomware"] = int(any("ransom" in s.get("name","") for s in sigs))
    features["has_packer"] = int(any("packer" in s.get("name","") for s in sigs))
    features["malscore"] = float(report.get("malscore", 0))

    # Behavior
    procs = report.get("behavior", {}).get("processes", [])
    features["num_processes"] = len(procs)
    all_calls = sum(len(p.get("calls", [])) for p in procs)
    features["num_api_calls"] = all_calls

    # Network
    network = report.get("network", {})
    features["num_dns"] = len(network.get("dns", []))
    features["num_tcp"] = len(network.get("tcp", []))
    features["num_udp"] = len(network.get("udp", []))
    features["num_http"] = len(network.get("http", []))

    # CAPE
    cape = report.get("CAPE", {})
    payloads = cape.get("payloads", []) if isinstance(cape, dict) else []
    features["num_cape_payloads"] = len(payloads)

    # File
    target = report.get("target", {}).get("file", {})
    features["file_size"] = target.get("size", 0)
    features["num_strings"] = len(target.get("strings", []))

    return features

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "/opt/CAPEv2/storage/analyses/15/reports/report.json"
    features = extract_features(path)
    print(json.dumps(features, indent=2))
