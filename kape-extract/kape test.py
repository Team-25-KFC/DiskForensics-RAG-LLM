#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kape_pipeline_artifact_v6.py — (2025-10-30)
AIM 마운트(너의 parser_split_i30_v2.py와 동일 로직) → KAPE(EventLogs, RegistryHives) 실행 → 언마운트
- Targets 결과(복사본)는 Output/{artifact}/ 에 저장
- Modules 결과는 JSON으로 Output/{artifact}/ModuleOutput/ 에 저장
"""

import os, sys, time, re, subprocess
from pathlib import Path

# -----------------------------
# 사용자 설정
# -----------------------------
AIM_EXE  = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH = r"H:\Laptop\Laptop.E01"
KAPE_EXE = r"C:\KAPE\kape.exe"

BASE_OUT = Path(r"C:\ccit 프로그램\Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

# 실행할 RECmd_* 모듈들 (콤마로 연결되어 KAPE --module 에 전달됨)
RECMD_MODULES = ",".join([
    "RECmd_AllRegExecutablesFoundOrRun",
    "RECmd_BasicSystemInfo",
    "RECmd_BCDBootVolume",
    "RECmd_InstalledSoftware",
    "RECmd_Kroll",
    "RECmd_Batch_MC",
    "RECmd_RegistryASEPs",
    "RECmd_SoftwareASEPs",
    "RECmd_SoftwareClassesASEPs",
    "RECmd_SoftwareWow6432ASEPs",
    "RECmd_SystemASEPs",
    "RECmd_UserActivity",
    "RECmd_UserClassesASEPs",
    # 필요시 여기에 추가
])

# -----------------------------
# 공용 유틸 (그대로)
# -----------------------------
def run(cmd, **kwargs):
    print(f"[CMD] {' '.join(cmd)}")
    return subprocess.run(cmd, text=True, capture_output=True, **kwargs)

def run_ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)

def ps_lines(cp):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

def safe_run(cmd, capture=True, timeout=None):
    try:
        if capture:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            res = subprocess.run(cmd, timeout=timeout)
        return res
    except Exception as e:
        class _R: pass
        r = _R()
        r.returncode = 1
        r.stdout = ""
        r.stderr = str(e)
        return r

MOUNT_STABILIZE_SEC = 5

def mount_e01():
    print("[ACTION] Mounting E01 image...")
    cmd = [AIM_EXE, "--mount", f"--filename={E01_PATH}", "--provider=LibEwf", "--readonly", "--online"]
    device_number = None
    disk_number = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            print("[AIM] " + line)
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev:
                device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy:
                disk_number = int(m_phy.group(1))
            if ("Mounted read only" in line) or ("Mounted online" in line):
                break
            if time.time() - start > 120:
                print("[WARN] AIM output parse timeout")
                break
        print(f"[INFO] Device: {device_number}, PhysicalDrive: {disk_number}")
        print(f"[INFO] Waiting {MOUNT_STABILIZE_SEC}s for Windows to recognize volumes...")
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception as e:
        print(f"[ERROR] Mount failed: {e}")
        return None, None

def dismount_e01(device_number=None):
    print("[ACTION] Dismounting virtual disk...")
    if device_number:
        cmd = [AIM_EXE, f"--dismount={device_number}"]
    else:
        cmd = [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True)
        print("[INFO] Dismount complete.")
    except Exception as e:
        print(f"[ERROR] Dismount failed: {e}")

def get_ntfs_volumes(disk_number):
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps)
    vols = ps_lines(r)
    guids = [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]
    print(f"[INFO] NTFS volumes found: {len(guids)}")
    return guids

def get_letter_for_volume(vol_path):
    ps = f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter"
    r = run_ps(ps)
    letter = (r.stdout or "").strip()
    if letter:
        return f"{letter}:"
    return None

# -----------------------------
# OS 볼륨 판정
# -----------------------------
def has_eventlogs_root(letter: str) -> bool:
    return os.path.isdir(os.path.join(f"{letter}\\", r"Windows\System32\winevt\Logs"))

def has_registry_root(letter: str) -> bool:
    cfg = os.path.join(f"{letter}\\", r"Windows\System32\config")
    return any(os.path.isfile(os.path.join(cfg, hive)) for hive in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY"))

# -----------------------------
# KAPE 실행
# -----------------------------
def kape_eventlogs(letter: str):
    artifact_name = f"eventlog_{letter[0]}"
    out_dir = BASE_OUT / artifact_name
    triage_dir = out_dir / "TargetOutput"
    module_dir = out_dir / "ModuleOutput"
    log_dir = out_dir / "Logs"
    for d in (triage_dir, module_dir, log_dir):
        d.mkdir(parents=True, exist_ok=True)

    cmd = [
        KAPE_EXE,
        "--tsource", letter,
        "--tdest", str(out_dir),
        "--target", "EventLogs",
        "--module", "EvtxECmd",
        "--msource", str(out_dir),          # TargetOutput를 모듈 입력으로 사용
        "--mdest", str(module_dir),
        "--mef", "json",
        "--vss", "false"
    ]
    print(f"[+] Running KAPE for {artifact_name} ...")
    log_path = log_dir / f"{artifact_name}_runlog.txt"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        for line in proc.stdout:
            print(line.strip()); lf.write(line)
    proc.wait()
    print(f"[OK] {artifact_name} completed → {module_dir}\n")

def kape_registry(letter: str):
    artifact_name = f"registry_{letter[0]}"
    out_dir = BASE_OUT / artifact_name
    triage_dir = out_dir / "TargetOutput"
    module_dir = out_dir / "ModuleOutput"
    log_dir = out_dir / "Logs"
    for d in (triage_dir, module_dir, log_dir):
        d.mkdir(parents=True, exist_ok=True)

    cmd = [
        KAPE_EXE,
        "--tsource", letter,
        "--tdest", str(out_dir),
        "--target", "RegistryHives",     # 정확한 타깃명
        "--module", RECMD_MODULES,       # 개별 RECmd_* 모듈들을 콤마로 지정
        "--msource", str(out_dir),       # Target 복사본을 소스로
        "--mdest", str(module_dir),
        "--mef", "json",
        "--vss", "false"
    ]
    print(f"[+] Running KAPE for {artifact_name} ...")
    log_path = log_dir / f"{artifact_name}_runlog.txt"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        for line in proc.stdout:
            print(line.strip()); lf.write(line)
    proc.wait()
    print(f"[OK] {artifact_name} completed → {module_dir}\n")

# -----------------------------
# MAIN
# -----------------------------
def main():
    if not os.path.exists(E01_PATH):
        print(f"[ERROR] E01 not found: {E01_PATH}")
        sys.exit(1)

    disk, dev = mount_e01()
    if disk is None:
        print("[ERROR] Mount failed. Exiting.")
        sys.exit(1)

    vols = get_ntfs_volumes(disk)
    if not vols:
        print("[ERROR] No NTFS volumes found. Dismounting and exit.")
        dismount_e01(dev)
        sys.exit(1)

    ran_any = False
    for vol in vols:
        letter = get_letter_for_volume(vol)
        if not letter:
            continue
        print(f"[PLAN] Volume: {vol} -> letter={letter}")

        if has_eventlogs_root(letter):
            kape_eventlogs(letter); ran_any = True
        else:
            print(f"[SKIP] {letter} : EventLogs 루트 없음")

        if has_registry_root(letter):
            kape_registry(letter); ran_any = True
        else:
            print(f"[SKIP] {letter} : Registry 루트 없음")

    dismount_e01(dev)
    if not ran_any:
        print("[WARN] 실행할 수 있는 OS 볼륨을 찾지 못했습니다. (EventLogs/Registry 경로 부재)")
    print(f"[DONE] All artifacts saved under {BASE_OUT}")

if __name__ == "__main__":
    main()