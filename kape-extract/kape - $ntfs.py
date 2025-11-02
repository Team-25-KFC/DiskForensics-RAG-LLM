#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
kape_ntfs_pipeline_final.py — (Win10/11, Python 3.11+)
AIM(E01) 마운트 → KAPE 타깃(1패스: 복사) → KAPE 모듈 9개(2패스: 파싱) → 언마운트

출력 구조:
  C:\Kape Output\$NFTS_<드라이브>\
    ├─ Artifacts\          (Targets 1패스 복사본)
    ├─ <모듈명>\*          (Modules 2패스 결과; CSV)
    └─ Logs\*.log          (실행 로그)

타깃(네 환경의 --tlist . 기준):
  $MFT, $Boot, $J, $LogFile, $SDS    ※ $I30은 타깃이 아니라 모듈(INDXRipper)로 파싱
"""

import os, sys, time, re, subprocess
from pathlib import Path

# -----------------------------
# 사용자 설정 (경로 고정)
# -----------------------------
AIM_EXE  = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH = r"H:\Laptop\Laptop.E01"
KAPE_EXE = r"C:\KAPE\kape.exe"

# 실행 파일 경로(존재 확인용)
MFTECMD_EXE        = Path(r"C:\KAPE\Modules\bin\MFTECmd.exe")
NTFSLOGTRACKER_EXE = Path(r"C:\KAPE\Modules\bin\NTFS Log Tracker CMD v1.9\NTFS_Log_Tracker_CMD.exe")
INDXRIPPER_EXE     = Path(r"C:\KAPE\Modules\bin\INDXRipper\INDXRipper.exe")

# 출력 루트
BASE_OUT = Path(r"C:\Kape Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

# -----------------------------
# 유틸
# -----------------------------
def run_ps(cmd: str):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True)

def ps_lines(cp):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

MOUNT_STABILIZE_SEC = 5

def mount_e01():
    """AIM 마운트. 성공 시 (disk_number, device_number) 반환."""
    cmd = [AIM_EXE, "--mount", f"--filename={E01_PATH}", "--provider=LibEwf", "--readonly", "--online"]
    device_number = None
    disk_number = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        assert proc.stdout
        for line in proc.stdout:
            line = line.strip()
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev:
                device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy:
                disk_number = int(m_phy.group(1))
            if "Mounted online" in line or "Mounted read only" in line:
                break
            if time.time() - start > 120:
                break
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception:
        return None, None

def dismount_e01(device_number=None):
    """AIM 언마운트."""
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True)
    except Exception:
        pass

def get_ntfs_volumes(disk_number: int):
    """해당 물리디스크의 NTFS 볼륨 GUID 경로 리스트 반환."""
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps)
    vols = ps_lines(r)
    return [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]

def get_letter_for_volume(vol_path: str):
    r = run_ps(f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter")
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

# -----------------------------
# 모듈 목록 (총 9)
# -----------------------------
MODULES_9 = [
    "MFTECmd_$MFT",
    "MFTECmd_$J",
    "MFTECmd_$Boot",
    "MFTECmd_$MFT_FileListing",
    "MFTECmd_$MFT_ProcessMFTSlack",
    "MFTECmd_$MFT_DumpResidentFiles",
    "NTFSLogTracker_$J",
    "NTFSLogTracker_$LogFile",
    "INDXRipper",
]

def prerequisites_ok() -> bool:
    ok = True
    if not MFTECMD_EXE.exists():
        print(f"[ERROR] MFTECmd.exe 없음: {MFTECMD_EXE}"); ok = False
    if not NTFSLOGTRACKER_EXE.exists():
        print(f"[ERROR] NTFS Log Tracker 없음: {NTFSLOGTRACKER_EXE}"); ok = False
    if not INDXRIPPER_EXE.exists():
        print(f"[ERROR] INDXRipper 없음: {INDXRIPPER_EXE}"); ok = False
    return ok

# -----------------------------
# 타깃 해석
# -----------------------------
# [코드 삽입 시작]
def get_available_targets() -> list[str]:
    """
    KAPE --tlist . 출력에서 타깃 이름을 파싱 ('Target: <Name> (.\Targets\...)').
    """
    try:
        proc = subprocess.run([KAPE_EXE, "--tlist", "."], capture_output=True, text=True)
        text = (proc.stdout or "") + (proc.stderr or "")
        names = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Target: "):
                name = line[len("Target: "):].strip()
                # 뒤의 " (.\Targets\...)" 잘라내기
                if " (" in name:
                    name = name.split(" (", 1)[0].strip()
                names.append(name)
        return names
    except Exception as e:
        print(f"[ERROR] --tlist 파싱 중 예외: {e}")
        return []
# [코드 삽입 끝]

# [코드 삽입 시작] (환경에 맞춘 타깃 후보)
TARGET_CANDIDATES = [
    "$MFT",
    "$Boot",
    "$J",        # USN Journal ($J)
    "$LogFile",
    "$SDS",
]
# [코드 삽입 끝]

def resolve_targets() -> list[str]:
    """--tlist 결과와 교집합을 취해 실제 존재하는 타깃만 반환."""
    avail = set(get_available_targets())
    resolved = [t for t in TARGET_CANDIDATES if t in avail]
    missing = [t for t in TARGET_CANDIDATES if t not in avail]
    if missing:
        print("[WARN] 존재하지 않는 타깃(무시): " + ", ".join(missing))
    if not resolved:
        print("[ERROR] 유효한 타깃을 찾지 못했습니다. (C:\\KAPE\\kape.exe --tlist . 로 확인)")
    else:
        print("[INFO] 사용 타깃: " + ", ".join(resolved))
    return resolved

# -----------------------------
# KAPE Targets 1패스
# -----------------------------
def run_kape_targets(letter: str, tdest: Path, targets: list[str], logs_dir: Path):
    """NTFS 메타데이터를 tdest(Artifacts)로 복사."""
    tdest.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "__targets__.log"
    if not targets:
        print("[ERROR] 실행할 타깃이 없습니다.")
        return False
    target_arg = ",".join(targets)
    cmd = [
        KAPE_EXE,
        "--tsource", letter,
        "--tdest",   str(tdest),
        "--target",  target_arg,
        "--vss",     "false",
    ]
    print(f"[RUN] Targets ({letter}) -> {target_arg}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout
    with open(log_path, "w", encoding="utf-8") as lf:
        for line in proc.stdout:
            lf.write(line.rstrip() + "\n")
    rc = proc.wait()
    ok = (rc == 0)
    print(f"[OK ] Targets ({letter})" if ok else f"[FAIL] Targets ({letter}) rc={rc}")
    return ok

# -----------------------------
# KAPE Modules 2패스
# -----------------------------
def run_kape_module(msource: str, artifact_dir: Path, module_name: str, logs_dir: Path):
    """타깃 복사본(msource)을 입력으로 모듈 실행 → CSV 산출."""
    mdest = artifact_dir / module_name
    mdest.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{module_name}.log"

    cmd = [
        KAPE_EXE,
        "--msource", msource,   # 타깃 복사본 경로(Artifacts)
        "--mdest",   str(mdest),
        "--module",  module_name,
        "--mef",     "csv",
        "--vss",     "false",
    ]

    print(f"[RUN] {module_name} (src={msource})")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout
    with open(log_path, "w", encoding="utf-8") as lf:
        for line in proc.stdout:
            lf.write(line.rstrip() + "\n")
    proc.wait()
    print(f"[OK ] {module_name} (src={msource})")

# -----------------------------
# MAIN
# -----------------------------
def main():
    # 필수 도구 확인
    for p in (KAPE_EXE, AIM_EXE, E01_PATH):
        if not os.path.exists(p):
            print(f"[ERROR] Missing: {p}")
            sys.exit(2)
    if not prerequisites_ok():
        sys.exit(3)

    # 타깃 해석
    resolved_targets = resolve_targets()
    if not resolved_targets:
        sys.exit(4)

    # 마운트
    disk, dev = mount_e01()
    if disk is None:
        print("[ERROR] Mount failed.")
        sys.exit(5)

    vols = get_ntfs_volumes(disk)
    if not vols:
        dismount_e01(dev)
        print("[ERROR] No NTFS volumes.")
        sys.exit(6)

    for vol in vols:
        letter = get_letter_for_volume(vol)
        if not letter:
            continue
        artifact_dir  = BASE_OUT / f"$NFTS_{letter[0]}"
        logs_dir      = artifact_dir / "Logs"
        artifacts_dir = artifact_dir / "Artifacts"  # 타깃 복사본
        logs_dir.mkdir(parents=True, exist_ok=True)

        # 1) Targets 1패스
        ok_t = run_kape_targets(letter, artifacts_dir, resolved_targets, logs_dir)

        # 2) Modules 2패스
        if ok_t:
            for module_name in MODULES_9:
                run_kape_module(str(artifacts_dir), artifact_dir, module_name, logs_dir)
        else:
            print(f"[SKIP] Modules: 타깃 복사 실패로 {letter}는 모듈 실행 생략")

    dismount_e01(dev)
    print(f"[DONE] Outputs → {BASE_OUT}")

if __name__ == "__main__":
    main()
