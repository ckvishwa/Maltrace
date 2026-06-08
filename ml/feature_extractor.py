"""
feature_extractor.py — Hardened behavioral feature extractor
=============================================================
Version 2 — replaces shallow 17-feature version.

Changes from v1:
  - Added process injection detection (VirtualAllocEx+WriteProcessMemory+CreateRemoteThread)
  - Added persistence detection (RegSetValueEx on autorun keys)
  - Added shadow copy deletion detection (vssadmin/wmic)
  - Added credential access detection (LSASS reads)
  - Added dropper detection (PE written to disk)
  - Added sleep evasion detection (NtDelayExecution > 60s)
  - Added keylogger detection (SetWindowsHookEx WH_KEYBOARD_LL)
  - Added UAC bypass detection (eventvwr/fodhelper)
  - Added network-before-files timing (C2 checkin pattern)
  - Added process tree analysis (suspicious spawn chains)
  - Added signature severity scoring (sum + max)
  - Added ratio features (api_density, sig_density)
  - Added memory injection regions
  - Added dropped PE count
  - Added file entropy
  - Added mutex count
  - Added unique IPs and domains
"""

import json
import math
import pefile
import os
from collections import Counter


def calculate_entropy(data):
    """Shannon entropy — detects encryption/packing."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def extract_api_sequence(calls):
    """Extract ordered API call list from a process."""
    return [c.get("api", "") for c in calls if isinstance(c, dict)]


def detect_process_injection(calls):
    """
    VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
    Classic process hollowing / injection chain.
    """
    apis = set(extract_api_sequence(calls))
    injection_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                      "NtWriteVirtualMemory", "NtCreateThreadEx", "RtlCreateUserThread"}
    return int(len(apis & injection_apis) >= 2)


def detect_file_encryption(calls):
    """
    ReadFile → WriteFile in rapid loop = ransomware file encryption.
    """
    apis = extract_api_sequence(calls)
    read_write_pairs = 0
    for i in range(len(apis) - 1):
        if apis[i] == "ReadFile" and apis[i + 1] == "WriteFile":
            read_write_pairs += 1
    return int(read_write_pairs > 10)


def detect_persistence(calls):
    """
    RegSetValueEx on autorun registry keys.
    """
    autorun_keys = [
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "Winlogon",
        "AppInit_DLLs",
        "Services",
        "Policies\\Explorer\\Run",
    ]
    for c in calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") in ("RegSetValueEx", "NtSetValueKey",
                            "RegCreateKeyExA", "RegCreateKeyExW"):
            args = str(c.get("arguments", ""))
            if any(k in args for k in autorun_keys):
                return 1
    return 0


def detect_shadow_copy_deletion(calls):
    """
    vssadmin delete shadows / wmic shadowcopy delete.
    Ransomware hallmark — prevents recovery.
    """
    shadow_patterns = [
        ("vssadmin", "delete"),
        ("wmic", "shadowcopy"),
        ("bcdedit", "recoveryenabled"),
        ("wbadmin", "delete"),
    ]
    for c in calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") in ("CreateProcessInternalW", "ShellExecuteExW",
                            "WinExec", "NtCreateUserProcess"):
            args = str(c.get("arguments", "")).lower()
            for pattern in shadow_patterns:
                if all(p in args for p in pattern):
                    return 1
    return 0


def detect_credential_access(calls):
    """
    LSASS memory read — credential dumping.
    T1003.001 OS Credential Dumping: LSASS Memory
    """
    for c in calls:
        if not isinstance(c, dict):
            continue
        args = str(c.get("arguments", "")).lower()
        if "lsass" in args and c.get("api") in (
            "OpenProcess", "ReadProcessMemory",
            "MiniDumpWriteDump", "NtOpenProcess"
        ):
            return 1
    return 0


def detect_dropper(calls):
    """
    Writes a PE file to disk (MZ header in WriteFile args).
    """
    for c in calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") == "WriteFile":
            buf = str(c.get("arguments", {}).get("buffer", ""))
            if buf.startswith("4d5a") or "MZ" in buf[:10]:
                return 1
    return 0

def detect_sleep_evasion(calls):
    for c in calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") in ("NtDelayExecution", "Sleep", "SleepEx",
                            "WaitForSingleObject"):
            args = c.get("arguments", {})

            if not isinstance(args, dict): continue
            # Handle both dict and list formats
            if isinstance(args, list):
                continue
            ms = args.get("milliseconds", 0) or args.get("DelayInterval", 0)
            try:
                if int(str(ms).replace("-", "")) > 60000:
                    return 1
            except (ValueError, TypeError):
                pass
    return 0


def detect_keylogger(calls):
    """
    SetWindowsHookEx with WH_KEYBOARD_LL (13) — keylogger hook.
    """
    for c in calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") == "SetWindowsHookExA":
            args = c.get("arguments", {})

            if not isinstance(args, dict): continue
            if str(args.get("idHook", "")) == "13":
                return 1
    return 0


def detect_uac_bypass(calls):
    """
    Common UAC bypass via registry or COM elevation.
    eventvwr, fodhelper, comspec patterns.
    """
    bypass_patterns = ["eventvwr", "fodhelper", "sdclt", "computerdefaults"]
    for c in calls:
        if not isinstance(c, dict):
            continue
        args = str(c.get("arguments", "")).lower()
        if any(p in args for p in bypass_patterns):
            if c.get("api") in ("RegSetValueEx", "ShellExecuteExW",
                                "CreateProcessInternalW"):
                return 1
    return 0


def detect_network_before_files(all_calls):
    """
    Network activity before file operations = C2 check-in pattern.
    """
    apis = extract_api_sequence(all_calls)
    net_apis  = {"connect", "send", "WSASend", "InternetOpenUrl",
                 "HttpSendRequest", "InternetConnectA"}
    file_apis = {"CreateFileW", "CreateFileA", "WriteFile", "ReadFile"}

    first_net  = next((i for i, a in enumerate(apis) if a in net_apis), None)
    first_file = next((i for i, a in enumerate(apis) if a in file_apis), None)

    if first_net is not None and first_file is not None:
        return int(first_net < first_file)
    return 0


def get_process_tree_features(procs):
    """
    Analyze process spawn chains for suspicious patterns.
    Office/browser spawning cmd/powershell = suspicious.
    """
    pid_map = {}
    for p in procs:
        if isinstance(p, dict):
            pid_map[p.get("pid")] = p

    suspicious_parents  = {"winword.exe", "excel.exe", "powerpnt.exe",
                           "chrome.exe", "firefox.exe", "outlook.exe",
                           "iexplore.exe", "msedge.exe"}
    suspicious_children = {"cmd.exe", "powershell.exe", "wscript.exe",
                           "cscript.exe", "mshta.exe", "rundll32.exe",
                           "regsvr32.exe", "certutil.exe"}

    suspicious_spawns = 0
    unique_names = set()

    for p in procs:
        if not isinstance(p, dict):
            continue
        pname  = p.get("process_name", "").lower()
        ppid   = p.get("ppid")
        parent = pid_map.get(ppid, {})
        pparent_name = parent.get("process_name", "").lower()
        unique_names.add(pname)

        if pparent_name in suspicious_parents and pname in suspicious_children:
            suspicious_spawns += 1

    return {
        "num_unique_processes":    len(unique_names),
        "suspicious_spawn_chains": suspicious_spawns,
    }



def static_features(filepath):
    """
    Pre-execution PE static analysis.
    Catches packed/encrypted files before sandbox execution.
    Reduces reliance on malscore by adding DNA-level features.
    """
    feats = {
        "pe_entropy":      0.0,  # max section entropy — high = packed/encrypted
        "pe_num_sections": 0,    # unusual count = suspicious
        "pe_has_upx":      0,    # UPX packer detected
        "pe_wx_section":   0,    # writable+executable section = self-unpacking
        "pe_num_imports":  0,    # import count — too few = packed, too many = suspicious
        "pe_is_64bit":     0,    # architecture
        "pe_is_signed":    0,    # code signing — legitimate software usually signed
        "pe_has_tls":      0,    # TLS callbacks — used by malware for anti-debug
    }
    try:
        pe = pefile.PE(filepath, fast_load=False)

        # Max section entropy
        entropies = []
        for s in pe.sections:
            try:
                entropies.append(s.get_entropy())
            except:
                pass
        feats["pe_entropy"] = round(max(entropies) if entropies else 0.0, 4)

        # Section analysis
        feats["pe_num_sections"] = len(pe.sections)
        for s in pe.sections:
            name = s.Name.decode(errors="ignore").strip("\x00").lower()
            # UPX packer
            if "upx" in name:
                feats["pe_has_upx"] = 1
            # Writable + Executable = self-unpacking code
            if (s.Characteristics & 0x20000000) and (s.Characteristics & 0x80000000):
                feats["pe_wx_section"] = 1

        # Import count
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            feats["pe_num_imports"] = sum(
                len(e.imports)
                for e in pe.DIRECTORY_ENTRY_IMPORT
                if hasattr(e, "imports")
            )

        # Architecture
        feats["pe_is_64bit"] = int(pe.FILE_HEADER.Machine == 0x8664)

        # Code signing
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            feats["pe_is_signed"] = 1

        # TLS callbacks — anti-debug trick
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            feats["pe_has_tls"] = 1

        pe.close()
    except Exception:
        pass  # Non-PE or corrupt file — return zeros

    return feats

def extract_features(report_path):
    with open(report_path) as f:
        report = json.load(f)

    features = {}

    # ── Signatures ────────────────────────────────────────────────────────────
    sigs = report.get("signatures", []) or []
    sig_names = [s.get("name", "") for s in sigs if isinstance(s, dict)]
    sig_severities = [int(s.get("severity", 1)) for s in sigs if isinstance(s, dict)]

    features["malscore"]          = float(report.get("malscore", 0) or 0)
    features["num_signatures"]    = len(sig_names)
    features["sig_severity_sum"]  = sum(sig_severities) if sig_severities else 0
    features["sig_severity_max"]  = max(sig_severities) if sig_severities else 0
    features["has_ransomware"]    = int(any("ransom"      in n for n in sig_names))
    features["has_antidebug"]     = int(any("antidebug"   in n for n in sig_names))
    features["has_antisandbox"]   = int(any("antisandbox" in n for n in sig_names))
    features["has_network_sig"]   = int(any("network"     in n for n in sig_names))
    features["has_stealth"]       = int(any("stealth"     in n for n in sig_names))
    features["has_packer"]        = int(any("packer"      in n for n in sig_names))
    features["has_infostealer"]   = int(any("stealer"     in n for n in sig_names))
    features["has_rat"]           = int(any("rat"         in n for n in sig_names))
    features["has_banker"]        = int(any("bank"        in n for n in sig_names))

    # ── Behavior ──────────────────────────────────────────────────────────────
    procs     = (report.get("behavior") or {}).get("processes", []) or []
    all_calls = []
    for p in procs:
        if isinstance(p, dict):
            calls = p.get("calls", []) or []
            all_calls.extend(calls)

    features["num_processes"]  = len(procs)
    features["num_api_calls"]  = len(all_calls)

    # Behavioral detections
    features["has_process_injection"]   = detect_process_injection(all_calls)
    features["has_file_encryption"]     = detect_file_encryption(all_calls)
    features["has_persistence"]         = detect_persistence(all_calls)
    features["has_shadow_deletion"]     = detect_shadow_copy_deletion(all_calls)
    features["has_credential_access"]   = detect_credential_access(all_calls)
    features["has_dropper"]             = detect_dropper(all_calls)
    features["has_sleep_evasion"]       = detect_sleep_evasion(all_calls)
    features["has_keylogger"]           = detect_keylogger(all_calls)
    features["has_uac_bypass"]          = detect_uac_bypass(all_calls)
    features["network_before_files"]    = detect_network_before_files(all_calls)

    # Process tree
    tree = get_process_tree_features(procs)
    features["num_unique_processes"]    = tree["num_unique_processes"]
    features["suspicious_spawn_chains"] = tree["suspicious_spawn_chains"]

    # Mutexes
    summary = (report.get("behavior") or {}).get("summary", {}) or {}
    features["num_mutexes"] = len(summary.get("mutexes", []) or [])

    # ── Network ───────────────────────────────────────────────────────────────
    net = report.get("network") or {}
    features["num_dns"]        = len(net.get("dns")  or [])
    features["num_tcp"]        = len(net.get("tcp")  or [])
    features["num_udp"]        = len(net.get("udp")  or [])
    features["num_http"]       = len(net.get("http") or [])
    features["num_smtp"]       = len(net.get("smtp") or [])
    features["unique_domains"] = len(set(
        d.get("request", "") for d in (net.get("dns") or [])
        if isinstance(d, dict)
    ))
    features["unique_ips"] = len(set(
        c.get("dst", "") for c in (net.get("tcp") or [])
        if isinstance(c, dict)
    ))

    # ── CAPE Payloads ─────────────────────────────────────────────────────────
    cape     = report.get("CAPE", {}) or {}
    payloads = cape.get("payloads", []) if isinstance(cape, dict) else []
    features["num_cape_payloads"] = len(payloads) if payloads else 0

    # ── Memory ────────────────────────────────────────────────────────────────
    memory = report.get("memory", {}) or {}
    features["num_injected_regions"] = len(memory.get("injected", []) or [])
    features["has_hollowing"]        = int(
        any("hollow" in str(m).lower() for m in memory.get("injected", []))
    )

    # ── Dropped Files ─────────────────────────────────────────────────────────
    dropped = report.get("dropped", []) or []
    features["num_dropped_files"] = len(dropped)
    features["dropped_pe_count"]  = sum(
        1 for d in dropped
        if isinstance(d, dict) and d.get("type", "").startswith("PE")
    )

    # ── Target File ───────────────────────────────────────────────────────────
    target = report.get("target", {}).get("file", {}) or {}
    features["file_size"]    = int(target.get("size", 0) or 0)
    features["num_strings"]  = len(target.get("strings", []) or [])
    features["file_entropy"] = float(target.get("entropy", 0.0) or 0.0)

    # ── Ratio Features (resist adversarial padding) ───────────────────────────
    features["api_density"] = round(
        features["num_api_calls"] / max(features["file_size"], 1), 6
    )
    features["sig_density"] = round(
        features["num_signatures"] / max(features["num_processes"], 1), 4
    )
    features["suspicious_api_ratio"] = round(
        sum([
            features["has_process_injection"],
            features["has_persistence"],
            features["has_shadow_deletion"],
            features["has_credential_access"],
            features["has_dropper"],
            features["has_sleep_evasion"],
        ]) / max(features["num_api_calls"] / 1000, 1),
        4
    )

    # ── Static PE features (pre-execution DNA analysis) ──────────────────
    # Get filepath from report target
    target_path = report.get("target", {}).get("file", {}).get("path", "")
    if target_path and os.path.exists(target_path):
        sf = static_features(target_path)
        features.update(sf)
    else:
        # Zeros if file not available
        features.update({
            "pe_entropy": 0.0, "pe_num_sections": 0,
            "pe_has_upx": 0, "pe_wx_section": 0,
            "pe_num_imports": 0, "pe_is_64bit": 0,
            "pe_is_signed": 0, "pe_has_tls": 0,
        })

    return features


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else \
           "/opt/CAPEv2/storage/analyses/15/reports/report.json"
    feats = extract_features(path)
    print(f"Total features: {len(feats)}\n")
    for k, v in sorted(feats.items()):
        print(f"  {k:<30} {v}")