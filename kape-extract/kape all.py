#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
kape_pipeline_v2_fixed.py — (Win10/11, Python 3.11+)
AIM(E01) 마운트 → KAPE 타깃(1패스: 복사) → KAPE 모듈(2패스: 파싱) → 언마운트

- 원본(kape_ntfs_pipeline_final.py)의 안정적인 2-pass 구조를 유지.
- 두 번째로 주신 파일의 타깃(Prefetch, Amcache 등)과 모듈(PECmd, LECmd 등)을 사용.
- 2패스 모듈 실행 시 msource 경로를 ...\Artifacts\<드라이브문자> 로 정확히 지정.

출력 구조:
  C:\Kape Output\$NFTS_<드라이브>\
    ├─ Artifacts\             (Targets 1패스 복사본)
    ├─ <모듈명>\* (Modules 2패스 결과; CSV)
    └─ Logs\*.log             (실행 로그)
"""

import os, sys, time, re, subprocess
from pathlib import Path

# -----------------------------
# 사용자 설정 (경로 고정)
# -----------------------------
AIM_EXE  = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH = r"H:\Laptop\Laptop.E01"
KAPE_EXE = r"C:\KAPE\kape.exe"

# 출력 루트
BASE_OUT = Path(r"C:\Kape Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

# -----------------------------
# 유틸
# -----------------------------
def run_ps(cmd: str):
    """PowerShell 명령을 실행하고 CompletedProcess 객체를 반환합니다."""
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True)

def ps_lines(cp):
    """PowerShell 실행 결과(stdout)를 줄바꿈 기준으로 정리하여 리스트로 반환합니다."""
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
        subprocess.run(cmd, check=True, capture_output=True) # stdout/stderr 숨김
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
    """볼륨 GUID 경로로 드라이브 문자 (예: "E:")를 반환합니다."""
    r = run_ps(f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter")
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

# -----------------------------
# 모듈 목록 (V2)
# -----------------------------
# KAPE가 네이티브 지원하므로, 개별 EXE 존재 여부 확인(prerequisites_ok)은 불필요.
MODULES_V2 = [
    "PECmd",
    "AmcacheParser",
    "AppCompatCacheParser",
    "LECmd", "JLECmd",
    "RBCmd",
    "SrumECmd",
    "SQLECmd",
    "SBECmd",
    "WxTCmd",
]

# -----------------------------
# 타깃 목록 (V2)
# -----------------------------
TARGETS_V2 = [
    "Prefetch",
    "Amcache",
    "RegistryHivesSystem",     # AppCompatCache용
    "LNKFilesAndJumpLists",
    "RecycleBin_DataFiles",    # RBCmd용
    "RecycleBin_InfoFiles",    # RBCmd용
    "SRUM",
    "Chrome",                  # SQLECmd, SBECmd용
    "EdgeChromium",            # SQLECmd, SBECmd용
    "RegistryHivesUser",       # WxTCmd용
    "WindowsTimeline",         # WxTCmd용
]

def kape_list_parse(output_text: str, prefix: str) -> set[str]:
    """--tlist 또는 --mlist 출력에서 이름만 파싱합니다."""
    names = set()
    for line in output_text.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            name = line[len(prefix):].strip()
            # 뒤의 " (.\Targets\...)" 잘라내기
            if " (" in name:
                name = name.split(" (", 1)[0].strip()
            names.add(name)
    return names

def resolve_lists() -> tuple[list[str], list[str]]:
    """KAPE --tlist, --mlist와 교집합을 취해 실제 존재하는 타깃/모듈만 반환."""
    print("[INFO] KAPE --tlist, --mlist 실행하여 타깃/모듈 목록 확인 중...")
    try:
        # Targets
        proc_t = subprocess.run([KAPE_EXE, "--tlist", "."], capture_output=True, text=True)
        text_t = (proc_t.stdout or "") + (proc_t.stderr or "")
        avail_t = kape_list_parse(text_t, "Target: ")

        # Modules
        proc_m = subprocess.run([KAPE_EXE, "--mlist", "."], capture_output=True, text=True)
        text_m = (proc_m.stdout or "") + (proc_m.stderr or "")
        avail_m = kape_list_parse(text_m, "Module: ")

    except Exception as e:
        print(f"[ERROR] kape.exe --tlist/--mlist 실행 중 예외 발생: {e}")
        return [], []

    resolved_t = [t for t in TARGETS_V2 if t in avail_t]
    resolved_m = [m for m in MODULES_V2 if m in avail_m]

    missing_t = [t for t in TARGETS_V2 if t not in avail_t]
    missing_m = [m for m in MODULES_V2 if m not in avail_m]

    if missing_t:
        print("[WARN] 존재하지 않는 타깃(무시): " + ", ".join(missing_t))
    if missing_m:
        print("[WARN] 존재하지 않는 모듈(무시): " + ", ".join(missing_m))

    if not resolved_t:
        print("[ERROR] 유효한 타깃을 찾지 못했습니다.")
    else:
        print("[INFO] 사용 타깃: " + ", ".join(resolved_t))

    if not resolved_m:
        print("[ERROR] 유효한 모듈을 찾지 못했습니다.")
    else:
        print("[INFO] 사용 모듈: " + ", ".join(resolved_m))

    return resolved_t, resolved_m

# -----------------------------
# KAPE Targets 1패스
# -----------------------------
def run_kape_targets(letter: str, tdest: Path, targets: list[str], logs_dir: Path):
    """아티팩트를 tdest(Artifacts)로 복사."""
    tdest.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "__targets__.log"
    if not targets:
        print("[ERROR] 실행할 타깃이 없습니다.")
        return False
        
    target_arg = ",".join(targets)
    cmd = [
        KAPE_EXE,
        "--tsource", letter,      # 예: "E:"
        "--tdest",   str(tdest),  # 예: C:\Kape Output\$NFTS_E\Artifacts
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
    mdest = artifact_dir / module_name  # 예: C:\Kape Output\$NFTS_E\<모듈명>
    mdest.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{module_name}.log"

    cmd = [
        KAPE_EXE,
        "--msource", msource,     # 1패스 결과물 경로 (예: ...\Artifacts\E)
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
    rc = proc.wait()

    # CSV 생성 여부 확인
    csvs = list(mdest.rglob("*.csv")) # 하위 폴더까지 검색
    if rc == 0 and csvs:
        print(f"[CSV] {module_name} -> {len(csvs)} CSV file(s) created.")
    elif rc == 0:
        print(f"[WARN] {module_name} completed, but no CSV files found in {mdest}")
    else:
        print(f"[FAIL] {module_name} (rc={rc}) - Check log: {log_path}")


# -----------------------------
# MAIN
# -----------------------------
def main():
    # 필수 도구 확인
    for p in (KAPE_EXE, AIM_EXE, E01_PATH):
        if not os.path.exists(p):
            print(f"[ERROR] Missing: {p}")
            sys.exit(2)

    # 타깃/모듈 해석
    resolved_targets, resolved_modules = resolve_lists()
    if not resolved_targets or not resolved_modules:
        sys.exit(4)

    # 마운트
    print("\n[INFO] E01 이미지 마운트 시도...")
    disk, dev = mount_e01()
    if disk is None:
        print("[ERROR] Mount failed.")
        sys.exit(5)
    print(f"[INFO] 마운트 성공: DiskNumber={disk}, DeviceNumber={dev}")

    try:
        vols = get_ntfs_volumes(disk)
        if not vols:
            print("[ERROR] No NTFS volumes found on mounted disk.")
            sys.exit(6)

        print(f"[INFO] 발견된 NTFS 볼륨: {', '.join(vols)}")

        for vol in vols:
            letter = get_letter_for_volume(vol)
            if not letter:
                print(f"[WARN] {vol}의 드라이브 문자를 찾을 수 없어 건너뜁니다.")
                continue
            
            print(f"\n===== PROCESSING DRIVE {letter} ({vol}) =====")
            drive_char = letter[0] # "E:" -> "E"
            
            artifact_dir  = BASE_OUT / f"$NFTS_{drive_char}"
            logs_dir      = artifact_dir / "Logs"
            artifacts_dir = artifact_dir / "Artifacts" # 타깃 복사본 저장 위치
            logs_dir.mkdir(parents=True, exist_ok=True)

            # 1) Targets 1패스
            ok_t = run_kape_targets(letter, artifacts_dir, resolved_targets, logs_dir)

            # 2) Modules 2패스
            if ok_t:
                # [중요] 1패스 결과물 경로는 ...\Artifacts\<드라이브문자> (예: ...\Artifacts\E)
                msource_for_modules = artifacts_dir / drive_char
                
                # msource 경로가 실제 존재하는지 확인
                if not (msource_for_modules.exists() and msource_for_modules.is_dir()):
                    print(f"[ERROR] 1패스 출력 폴더를 찾을 수 없습니다: {msource_for_modules}")
                    print(f"[INFO] 대신 {artifacts_dir} 폴더를 사용합니다. (결과가 없을 수 있음)")
                    msource_for_modules = artifacts_dir # Fallback
                
                print(f"[INFO] 2패스 모듈 입력(msource): {msource_for_modules}")

                for module_name in resolved_modules:
                    run_kape_module(str(msource_for_modules), artifact_dir, module_name, logs_dir)
            else:
                print(f"[SKIP] Modules: 타깃 복사 실패로 {letter}는 모듈 실행 생략")

    finally:
        # 언마운트
        print("\n[INFO] E01 이미지 언마운트...")
        dismount_e01(dev)
        print(f"[DONE] Outputs → {BASE_OUT}")

if __name__ == "__main__":
    main()
