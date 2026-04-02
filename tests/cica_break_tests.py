import json, os, sys, time, requests, tempfile
API_URL = "http://localhost:5000/predict"
BRIDGE = "http://192.168.75.1:9090"
REPORT = "/opt/CAPEv2/storage/analyses/15/reports/report.json"
MODEL = "/opt/CAPEv2/ml/model.pkl"
PASS_,FAIL_,INFO_ = "✅","❌","ℹ️"
results = []
def log(name, status, detail):
    print(f"  {status} {name}: {detail}")
    results.append((name,status,detail))
def test1():
    print("\nTEST 1 — Missing keys")
    for name, data in [("empty",{}),("no sigs",{"malscore":5.0}),("null vals",{"malscore":None,"signatures":None})]:
        with tempfile.NamedTemporaryFile(mode='w',suffix='.json',delete=False) as f:
            json.dump(data,f); tmp=f.name
        try:
            r=requests.post(API_URL,files={"report":open(tmp)},timeout=10)
            log(name,PASS_ if r.status_code==200 else FAIL_,f"HTTP {r.status_code}")
        except Exception as e: log(name,FAIL_,str(e)[:60])
        finally: os.unlink(tmp)
def test2():
    print("\nTEST 2 — Corrupt JSON")
    for name,content in [("empty",b""),("truncated",b'{"malscore":5'),("garbage",b"not json")]:
        with tempfile.NamedTemporaryFile(suffix='.json',delete=False) as f:
            f.write(content); tmp=f.name
        try:
            r=requests.post(API_URL,files={"report":("r.json",open(tmp,'rb'))},timeout=10)
            log(name,PASS_ if r.status_code in [400,500] else FAIL_,f"HTTP {r.status_code}")
        except Exception as e: log(name,FAIL_,str(e)[:60])
        finally: os.unlink(tmp)
def test3():
    print("\nTEST 3 — Model missing")
    if not os.path.exists(REPORT): print("  Need report 15"); return
    bak=MODEL+".bak"
    if os.path.exists(MODEL): os.rename(MODEL,bak)
    try:
        r=requests.post(API_URL,files={"report":open(REPORT)},timeout=10)
        log("no model",PASS_ if r.status_code in [400,500] else FAIL_,f"HTTP {r.status_code}")
    except Exception as e: log("no model",FAIL_,str(e)[:60])
    finally:
        if os.path.exists(bak): os.rename(bak,MODEL)
def test4():
    print("\nTEST 4 — Bridge")
    try:
        r=requests.get(f"{BRIDGE}/health",timeout=3)
        log("bridge",PASS_,f"HTTP {r.status_code}")
    except: log("bridge",INFO_,"not reachable — start vmrun_bridge.py on Windows host")
def test5():
    print("\nTEST 5 — Large report")
    big={"malscore":8.0,"signatures":[{"name":f"sig_{i}","severity":2} for i in range(500)],"behavior":{"processes":[{"pid":i,"calls":[{"api":"CreateFile","arguments":{}}]*100} for i in range(10)],"summary":{}},"network":{},"CAPE":{"payloads":[]},"target":{"file":{"size":9999,"strings":["x"]*1000}}}
    with tempfile.NamedTemporaryFile(mode='w',suffix='.json',delete=False) as f:
        json.dump(big,f); tmp=f.name
    size=os.path.getsize(tmp)/1024/1024; t=time.time()
    try:
        r=requests.post(API_URL,files={"report":open(tmp)},timeout=30)
        log(f"large({size:.1f}MB)",PASS_ if r.status_code==200 else FAIL_,f"HTTP {r.status_code} in {time.time()-t:.1f}s")
    except Exception as e: log("large",FAIL_,str(e)[:60])
    finally: os.unlink(tmp)
def test6():
    print("\nTEST 6 — Pipeline check")
    for name,url in [("CAPEv2","http://localhost:8000"),("Flask","http://localhost:5000/health"),("Bridge",BRIDGE)]:
        try:
            r=requests.get(url,timeout=5); log(name,PASS_,f"HTTP {r.status_code}")
        except Exception as e: log(name,FAIL_,str(e)[:50])
    log("model.pkl",PASS_ if os.path.exists(MODEL) else FAIL_,"exists" if os.path.exists(MODEL) else "missing")
tests={1:test1,2:test2,3:test3,4:test4,5:test5,6:test6}
arg=sys.argv[1] if len(sys.argv)>1 else "all"
if arg=="all":
    for t in tests.values(): t()
else:
    tests.get(int(arg),lambda:print("Invalid"))()
print(f"\n{'='*50}")
passed=sum(1 for _,s,_ in results if s==PASS_)
failed=sum(1 for _,s,_ in results if s==FAIL_)
print(f"✅ {passed} passed  ❌ {failed} failed")
