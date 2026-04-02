import json, os, csv
ANALYSES_DIR = "/opt/CAPEv2/storage/analyses"
OUTPUT_CSV = "/opt/CAPEv2/ml/dataset.csv"
LABELS = {
    "15": {"label": 1, "family": "ransomware", "name": "WannaCry"},
    "12": {"label": 0, "family": "benign",     "name": "EICAR"},
}
def extract_features(path):
    with open(path) as f: r = json.load(f)
    sigs = r.get("signatures",[]) or []
    sig_names = [s.get("name","") for s in sigs if isinstance(s,dict)]
    procs = r.get("behavior",{}).get("processes",[]) or []
    net = r.get("network",{}) or {}
    cape = r.get("CAPE",{}) or {}
    fi = r.get("target",{}).get("file",{}) or {}
    return {"malscore":float(r.get("malscore",0) or 0),"num_signatures":len(sig_names),"has_ransomware":int(any("ransom" in n for n in sig_names)),"has_antidebug":int(any("antidebug" in n for n in sig_names)),"has_antisandbox":int(any("antisandbox" in n for n in sig_names)),"has_network_sig":int(any("network" in n for n in sig_names)),"has_stealth":int(any("stealth" in n for n in sig_names)),"has_packer":int(any("packer" in n for n in sig_names)),"num_processes":len(procs),"num_api_calls":sum(len(p.get("calls",[]) or []) for p in procs if isinstance(p,dict)),"num_dns":len(net.get("dns",[])),"num_tcp":len(net.get("tcp",[])),"num_udp":len(net.get("udp",[])),"num_http":len(net.get("http",[])),"num_cape_payloads":len(cape.get("payloads",[]) or []) if isinstance(cape,dict) else 0,"file_size":int(fi.get("size",0) or 0),"num_strings":len(fi.get("strings",[]) or [])}
rows = []
for task_id, meta in sorted(LABELS.items(), key=lambda x: int(x[0])):
    path = f"{ANALYSES_DIR}/{task_id}/reports/report.json"
    if not os.path.exists(path):
        print(f"  [SKIP] Task {task_id}"); continue
    try:
        feats = extract_features(path)
        rows.append({"task_id":task_id,"name":meta["name"],"family":meta["family"],"label":meta["label"],**feats})
        print(f"  [{'MALWARE' if meta['label'] else 'BENIGN '}] Task {task_id} — {meta['name']}")
    except Exception as e:
        print(f"  [ERROR] Task {task_id}: {e}")
if rows:
    with open(OUTPUT_CSV,"w",newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"\nSaved: {OUTPUT_CSV} ({len(rows)} samples)")
