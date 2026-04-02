#!/usr/bin/env python3
import sys, json, pickle, os
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
FEATURE_COLS = ["malscore","num_signatures","has_ransomware","has_antidebug","has_antisandbox","has_network_sig","has_stealth","has_packer","num_processes","num_api_calls","num_dns","num_tcp","num_udp","num_http","num_cape_payloads","file_size","num_strings"]
def extract_features(path):
    with open(path) as f: r = json.load(f)
    sigs = r.get("signatures",[]) or []
    sig_names = [s.get("name","") for s in sigs if isinstance(s,dict)]
    procs = r.get("behavior",{}).get("processes",[]) or []
    net = r.get("network",{}) or {}
    cape = r.get("CAPE",{}) or {}
    fi = r.get("target",{}).get("file",{}) or {}
    return {"malscore":float(r.get("malscore",0) or 0),"num_signatures":len(sig_names),"has_ransomware":int(any("ransom" in n for n in sig_names)),"has_antidebug":int(any("antidebug" in n for n in sig_names)),"has_antisandbox":int(any("antisandbox" in n for n in sig_names)),"has_network_sig":int(any("network" in n for n in sig_names)),"has_stealth":int(any("stealth" in n for n in sig_names)),"has_packer":int(any("packer" in n for n in sig_names)),"num_processes":len(procs),"num_api_calls":sum(len(p.get("calls",[]) or []) for p in procs if isinstance(p,dict)),"num_dns":len(net.get("dns",[])),"num_tcp":len(net.get("tcp",[])),"num_udp":len(net.get("udp",[])),"num_http":len(net.get("http",[])),"num_cape_payloads":len(cape.get("payloads",[]) or []) if isinstance(cape,dict) else 0,"file_size":int(fi.get("size",0) or 0),"num_strings":len(fi.get("strings",[]) or [])}
def predict(path):
    feats = extract_features(path)
    with open(MODEL_PATH,"rb") as f: data = pickle.load(f)
    clf = data["model"]
    prob = clf.predict_proba([list(feats.values())])[0]
    pred = clf.predict([list(feats.values())])[0]
    verdict = "MALWARE" if pred==1 else "BENIGN"
    conf = round(float(max(prob))*100,1)
    top = sorted(feats.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
    print("="*50)
    print(f"  VERDICT:    {verdict}")
    print(f"  CONFIDENCE: {conf}%")
    print(f"  MALWARE P:  {round(float(prob[1])*100,1)}%")
    print("-"*50)
    print("  TOP INDICATORS:")
    for k,v in top:
        if v > 0: print(f"    {k:<25} {v}")
    print("="*50)
if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python predict.py <report.json>"); sys.exit(1)
    predict(sys.argv[1])
