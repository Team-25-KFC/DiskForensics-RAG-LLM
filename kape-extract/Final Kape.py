#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, re, subprocess
from pathlib import Path

# =========================
# 사용자 설정
# =========================
AIM_EXE  = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH = r"H:\Laptop\Laptop.E01"
KAPE_EXE = Path(r"D:\KAPE\kape.exe")

BASE_OUT = Path(r"D:\Kape Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

MOUNT_STABILIZE_SEC = 15  # 마운트 후 안정화 대기(초)

# =========================
# 타깃 서브셋 (네가 지정한 목록만 복사)
# =========================
TARGET_SUBSET = [
    # CertUtil 인증서
    "CertUtil",

    # 보안 제품/로그
    "Antivirus", "WindowsDefender", "WinDefendDetectionHist", "ManageEngineLogs",
    "Avast", "AVG", "AviraAVLogs", "Bitdefender", "Combofix", "Emsisoft", "ESET",
    "FSecure", "Malwarebytes", "McAfee", "McAfee_ePO", "RogueKiller", "SecureAge",
    "SentinelOne", "Sophos", "SUPERAntiSpyware", "TotalAV", "VIPRE", "Webroot",

    # APP
    "OutlookPSTOST", "MicrosoftTeams", "MicrosoftToDo", "WindowsYourPhone", "Slack",
    "Telegram", "Discord", "Zoom", "MicrosoftOneNote", "MicrosoftStickyNotes",
    "Notepad++", "VLC Media Player",

    # 시작프로그램
    "StartupFolders", "StartupInfo", "ScheduledTasks", "SDB",
]

# =========================
# 유틸
# =========================
def sh(args, cwd=None, capture=False) -> int | tuple[int, str]:
    cp = subprocess.run(args, cwd=str(cwd) if cwd else None,
                        capture_output=capture, text=capture)
    if capture:
        return cp.returncode, (cp.stdout or "")
    return cp.returncode

def run_ps(cmd: str):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True)

def ps_lines(cp: subprocess.CompletedProcess) -> list[str]:
    if not cp or cp.stdout is None:
        return []
    return [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def has_files(p: Path) -> bool:
    if not p.exists():
        return False
    for _ in p.rglob("*"):
        if _.is_file():
            return True
    return False

def norm_drive_label(d: str) -> str:
    return d.rstrip(':\\').upper()

# =========================
# AIM 마운트 (네 스니펫 그대로)
# =========================
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

def get_ntfs_volumes(disk_number: int):
    """해당 물리디스크의 NTFS 볼륨 GUID 경로 리스트 반환."""
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps)
    vols = ps_lines(r)
    return [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]

def get_letter_for_volume(vol_path: str):
    """볼륨 GUID 경로로 드라이브 문자 (예: 'E:') 반환."""
    r = run_ps(f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter")
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

def dismount_e01(device_number=None):
    """AIM 언마운트."""
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except Exception:
        pass

# =========================
# KAPE 타깃(복사) – 네가 고른 서브셋만
# =========================
def run_kape_targets_subset(drive_letter: str, out_root: Path) -> int:
    allow = ",".join(TARGET_SUBSET)
    tdest = out_root / "Artifacts" / norm_drive_label(drive_letter)
    ensure_dir(tdest)
    return sh([
        str(KAPE_EXE),
        "--tsource", f"{drive_letter}\\",
        "--tdest",   str(tdest),
        "--target",  allow,
        "--vss", "false"
    ])

# =========================
# 개별 EXE 경로 (직접 호출용)
# =========================
RECMD_EXE      = Path(r"D:\KAPE\Modules\bin\RECmd\RECmd.exe")
RECMD_REB_DIR  = Path(r"D:\KAPE\Modules\bin\RECmd\BatchExamples")
SQLECMD_EXE    = Path(r"D:\KAPE\Modules\bin\SQLECmd\SQLECmd.exe")
SBECMD_EXE     = Path(r"D:\KAPE\Modules\bin\SBECmd.exe")
INDXRIP_EXE    = Path(r"D:\KAPE\Modules\bin\INDXRipper\INDXRipper.exe")
MFTECMD_EXE    = Path(r"D:\KAPE\Modules\bin\MFTECmd.exe")
BSTRINGS_EXE   = Path(r"D:\KAPE\Modules\bin\bstrings.exe")
SUMECMD_EXE    = Path(r"D:\KAPE\Modules\bin\SumECmd.exe")
WXTCMD_EXE     = Path(r"D:\KAPE\Modules\bin\WxTCmd.exe")
# // [코드 삽입 시작] 개별 EXE 경로 추가
EVTXECMD_EXE  = Path(r"D:\KAPE\Modules\bin\EvtxECmd\EvtxECmd.exe")
LECMD_EXE     = Path(r"D:\KAPE\Modules\bin\LECmd.exe")
JLECMD_EXE    = Path(r"D:\KAPE\Modules\bin\JLECmd.exe")

AMCACHE_EXE   = Path(r"D:\KAPE\Modules\bin\AmcacheParser.exe")
APPCOMPAT_EXE = Path(r"D:\KAPE\Modules\bin\AppCompatCacheParser.exe")

RBCMD_EXE     = Path(r"D:\KAPE\Modules\bin\RBCmd.exe")
RFCMD_EXE     = Path(r"D:\KAPE\Modules\bin\RecentFileCacheParser.exe")  # RecentFileCacheParser.exe

NTFSLOG_EXE   = Path(r"D:\KAPE\Modules\bin\NTFS Log Tracker CMD v1.9\NTFS_Log_Tracker_CMD.exe")
VSCMOUNT_EXE  = Path(r"D:\KAPE\Modules\bin\VSCMount\VSCMount.exe")      # 폴더 내 exe명이 다르면 이름만 맞춰줘
# // [코드 삽입 끝]


# =========================
# KAPE 모듈 호출 (msource = 드라이브 루트)
# =========================
def run_kape_module(msource: Path, mdest: Path, module_name: str) -> int:
    ensure_dir(mdest)
    return sh([
        str(KAPE_EXE),
        "--msource", str(msource),
        "--mdest",   str(mdest),
        "--module",  module_name
    ])

# =========================
# 모듈 실행 – 드라이브 루트 직접 스캔
# =========================
def run_modules_for_drive(drive_letter: str):
    safe = norm_drive_label(drive_letter)
    drive_root = Path(f"{drive_letter}\\")      # E:\
    out_root   = BASE_OUT / safe
    ensure_dir(out_root)

    WINDOWS = drive_root / "Windows"
    SYS32   = WINDOWS / "System32"
    USERS   = drive_root / "Users"

    # --- KAPE 모듈 (msource=드라이브 루트) ---
    for mod in ["EvtxECmd", "PECmd", "LECmd", "JLECmd", "AmcacheParser"]:
        dest = out_root / mod
        rc = run_kape_module(drive_root, dest, mod)
        print(f"[{mod}] rc={rc}, files={has_files(dest)}")

    # --- RECmd (.reb 배치) ---
    dest = out_root / "RECmd"; ensure_dir(dest)
    software_hive = SYS32 / "config" / "SOFTWARE"
    system_hive   = SYS32 / "config" / "SYSTEM"

    if software_hive.exists() and (RECMD_REB_DIR / "RECmd_InstalledSoftware.reb").exists():
        sh([str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_InstalledSoftware.reb"),
            "-f", str(software_hive), "--csv", str(dest), "--nl"], cwd=RECMD_EXE.parent)
        print("[RECmd InstalledSoftware] done")
    else:
        print("[RECmd InstalledSoftware] skipped (hive or reb missing)")

    if system_hive.exists() and (RECMD_REB_DIR / "RECmd_SystemASEPs.reb").exists():
        sh([str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_SystemASEPs.reb"),
            "-f", str(system_hive), "--csv", str(dest), "--nl"], cwd=RECMD_EXE.parent)
        print("[RECmd SystemASEPs] done")
    else:
        print("[RECmd SystemASEPs] skipped (hive or reb missing)")

    if USERS.exists() and (RECMD_REB_DIR / "RECmd_UserActivity.reb").exists():
        sh([str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_UserActivity.reb"),
            "-d", str(USERS), "--csv", str(dest), "--nl"], cwd=RECMD_EXE.parent)
        print("[RECmd UserActivity] done")
    else:
        print("[RECmd UserActivity] skipped (users or reb missing)")

    # --- SQLECmd (--hunt, -r 없음) ---
    dest = out_root / "SQLECmd"; ensure_dir(dest)
    if USERS.exists():
        sh([str(SQLECMD_EXE), "-d", str(USERS), "--csv", str(dest), "--hunt"], cwd=SQLECMD_EXE.parent)
        print("[SQLECmd] done")
    else:
        print("[SQLECmd] skipped (Users missing)")

    # --- SBECmd (-r 없음) ---
    dest = out_root / "SBECmd"; ensure_dir(dest)
    if USERS.exists():
        sh([str(SBECMD_EXE), "-d", str(USERS), "--csv", str(dest), "--dedupe", "--nl"], cwd=SBECMD_EXE.parent)
        print("[SBECmd] done")
    else:
        print("[SBECmd] skipped (Users missing)")

    # --- INDXRipper (라이브 디스크 핸들) ---
    dest = out_root / "INDXRipper"; ensure_dir(dest)
    if drive_root.exists():
        device = r"\\.\%s" % drive_letter   # "\\.\E:"
        out_csv = dest / "indx.csv"
        sh([str(INDXRIP_EXE), device, str(out_csv), "-f", "csv", "--dedup"], cwd=INDXRIP_EXE.parent)
        print(f"[INDXRipper] file_exists={out_csv.exists()}")
    else:
        print("[INDXRipper] skipped (drive not mounted)")

    # --- MFTECmd ($MFT/$Boot) ---
    dest = out_root / "MFTECmd"; ensure_dir(dest)
    if drive_root.exists():
        mft  = Path(f"{drive_letter}\\$MFT")
        boot = Path(f"{drive_letter}\\$Boot")
        if mft.exists():
            sh([str(MFTECMD_EXE), "-f", str(mft),  "--csv", str(dest)], cwd=MFTECMD_EXE.parent)
            sh([str(MFTECMD_EXE), "-f", str(mft),  "--csv", str(dest), "--recover-slack"], cwd=MFTECMD_EXE.parent)
        if boot.exists():
            sh([str(MFTECMD_EXE), "-f", str(boot), "--csv", str(dest)], cwd=MFTECMD_EXE.parent)
        print("[MFTECmd] done")
    else:
        print("[MFTECmd] skipped (drive not mounted)")

    # --- bstrings (-r 없음) ---
    dest = out_root / "bstrings"; ensure_dir(dest)
    if USERS.exists():
        sh([str(BSTRINGS_EXE), "-d", str(USERS), "-o", str(dest / "bstrings.txt"), "-s"], cwd=BSTRINGS_EXE.parent)
        print("[bstrings] done")
    else:
        print("[bstrings] skipped (Users missing)")

    # --- SumECmd (-r 없음) ---
    dest = out_root / "SumECmd"; ensure_dir(dest)
    if USERS.exists():
        sh([str(SUMECMD_EXE), "-d", str(USERS), "--csv", str(dest)], cwd=SUMECMD_EXE.parent)
        print("[SumECmd] done")
    else:
        print("[SumECmd] skipped (Users missing)")

    # --- WxTCmd (ActivitiesCache.db) ---
    dest = out_root / "WxTCmd"; ensure_dir(dest)
    if USERS.exists():
        ac_list = list(USERS.rglob("ActivitiesCache.db"))
        if ac_list:
            target = sorted(ac_list, key=lambda p: p.stat().st_mtime, reverse=True)[0]
            sh([str(WXTCMD_EXE), "-f", str(target), "--csv", str(dest)], cwd=WXTCMD_EXE.parent)
            print("[WxTCmd] done")
        else:
            print("[WxTCmd] skipped (ActivitiesCache.db not found)")
    else:
        print("[WxTCmd] skipped (Users missing)")

    # --- SrumECmd (KAPE 모듈: 네 mkape Processors 정의 사용) ---
    dest = out_root / "SrumECmd"; ensure_dir(dest)
    run_kape_module(drive_root, dest, "SrumECmd")
    print("[SrumECmd via KAPE] done")

# =========================
# 메인
# =========================
def main():
    print("=== 1) AIM Mount ===")
    disk_number, device_number = mount_e01()
    if disk_number is None:
        print("[AIM] 마운트 실패")
        return

    vols = get_ntfs_volumes(disk_number)
    letters = []
    for v in vols:
        lt = get_letter_for_volume(v)
        if lt:
            letters.append(lt)
    letters = sorted(set(letters))
    print(f"[AIM] NTFS 볼륨 드라이브: {', '.join(letters) if letters else '(없음)'}")

    # 2) (독립) 타깃 서브셋 복사
    print("\n=== 2) KAPE Targets(copy subset) ===")
    for d in letters:
        out_root = BASE_OUT / norm_drive_label(d)
        ensure_dir(out_root)
        rc = run_kape_targets_subset(d, out_root)
        print(f"[Targets {d}] rc={rc}")

    # 3) (독립) 모듈 파싱 – 드라이브 루트 직접 스캔
    print("\n=== 3) Modules(parse from mounted drive) ===")
    for d in letters:
        print(f"\n--- Modules pass: {d} ---")
        run_modules_for_drive(d)

    print("\n=== Dismount ===")
    dismount_e01(None)
    print("[AIM] dismount issued")

if __name__ == "__main__":
    main()
