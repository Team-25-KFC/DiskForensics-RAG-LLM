#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, re, shutil, subprocess
from pathlib import Path

# =========================
# 사용자 설정
# =========================
AIM_EXE  = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH = r"H:\Laptop\Laptop.E01"
KAPE_EXE = Path(r"D:\KAPE\kape.exe")

BASE_OUT = Path(r"D:\Kape Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

MOUNT_STABILIZE_SEC = 15
USE_ARTIFACTS_FOR_MODULES = True

# =========================
# 타깃 서브셋 (화이트리스트)
# =========================
TARGET_SUBSET = [
    # $NTFS
    "$MFT", "$MFTMirr", "$LogFile", "$Boot", "$SDS", "$T", "$J",
    # 레지스트리〔USB 포함 흡수〕
    "RegistryHives", "RegistryHivesSystem", "RegistryHivesUser", "RegistryHivesOther",
    "GroupPolicy", "USBDevicesLogs",
    # 이벤트로그
    "EventLogs", "EventTraceLogs", "EventTranscriptDB", "ApplicationEvents", "BITS", "CBS",
    "WindowsPowerDiagnostics", "WindowsTelemetryDiagnosticsLegacy", "WindowsFirewall",
    "WBEM", "WER", "WindowsIndexSearch", "WindowsNotificationsDB", "WindowsOSUpgradeArtifacts",
    # 실행흔적
    "Amcache", "LNKFilesAndJumpLists", "PowerShellConsole", "RDPLogs",
    # 캐시
    "Prefetch", "RecentFileCache", "Syscache", "ThumbCache", "JavaWebCache", "OfficeDocumentCache",
    # 시작프로그램
    "StartupFolders", "StartupInfo", "ScheduledTasks", "SDB",
    # 타임라인 / 활동기록
    "SRUM", "WindowsTimeline", "OfficeAutosave", "OfficeDiagnostics",
    # 브라우저
    "Chrome", "ChromeExtensions", "ChromeFileSystem", "Edge", "EdgeChromium", "InternetExplorer",
    # 클라우드
    "OneDrive_Metadata", "OneDrive_UserFiles",
    # APP
    "OutlookPSTOST", "MicrosoftTeams", "MicrosoftToDo", "WindowsYourPhone", "Slack",
    "Telegram", "Discord", "Zoom", "MicrosoftOneNote", "MicrosoftStickyNotes",
    "Notepad++", "VLC Media Player",
    # 보안
    "Antivirus", "WindowsDefender", "WinDefendDetectionHist", "ManageEngineLogs",
    "Avast", "AVG", "AviraAVLogs", "Bitdefender", "Combofix", "Emsisoft", "ESET",
    "FSecure", "Malwarebytes", "McAfee", "McAfee_ePO", "RogueKiller", "SecureAge",
    "SentinelOne", "Sophos", "SUPERAntiSpyware", "TotalAV", "VIPRE", "Webroot",
    # 휴지통
    "RecycleBin_DataFiles", "RecycleBin_InfoFiles",
    # 인증서
    "CertUtil",
]

# =========================
# 공용 유틸
# =========================
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
    if not p.exists(): return False
    for _ in p.rglob("*"):
        if _.is_file(): return True
    return False

def norm_drive_label(d: str) -> str:
    return d.rstrip(':\\').upper()

def run_and_log(cmd: list[str], log_path: Path, cwd: Path|None=None) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print("[CMD]", " ".join(map(str, cmd)))
    with open(log_path, "w", encoding="utf-8") as lf:
        try:
            proc = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert proc.stdout
            for line in proc.stdout:
                print(line.rstrip())
                lf.write(line)
            rc = proc.wait()
        except Exception as e:
            rc = 1
            em = f"[EXC] {e}\n"
            print(em); lf.write(em)
    return rc

# =========================
# AIM 마운트
# =========================
def mount_e01():
    cmd = [AIM_EXE, "--mount", f"--filename={E01_PATH}", "--provider=LibEwf", "--readonly", "--online"]
    device_number, disk_number = None, None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        assert proc.stdout
        for line in proc.stdout:
            line = line.strip()
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev: device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy: disk_number = int(m_phy.group(1))
            if ("Mounted online" in line) or ("Mounted read only" in line): break
            if time.time() - start > 120: break
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception:
        return None, None

def get_ntfs_volumes(disk_number: int):
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps)
    vols = ps_lines(r)
    return [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]

def get_letter_for_volume(vol_path: str):
    r = run_ps(f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter")
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

def dismount_e01(device_number=None):
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except Exception:
        pass

# =========================
# KAPE 타깃(복사)
# =========================
def run_kape_targets_subset(drive_letter: str, out_root: Path) -> int:
    allow = ",".join(TARGET_SUBSET)
    tdest = out_root / "Artifacts" / norm_drive_label(drive_letter)
    logs  = out_root / "Logs"
    ensure_dir(tdest)
    cmd = [str(KAPE_EXE), "--tsource", f"{drive_letter}\\", "--tdest", str(tdest),
           "--target", allow, "--vss", "false"]
    return run_and_log(cmd, logs / f"targets_{norm_drive_label(drive_letter)}.log")

# =========================
# 개별 EXE 경로
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

# =========================
# KAPE 모듈 호출 (로그 포함)
# =========================
def run_kape_module(msource: Path, mdest: Path, module_name: str) -> int:
    ensure_dir(mdest)
    logs = mdest.parent / "Logs"
    cmd = [str(KAPE_EXE), "--msource", str(msource), "--mdest", str(mdest), "--module", module_name]
    return run_and_log(cmd, logs / f"module_{module_name}.log")

# =========================
# 모듈 실행 – 하이브리드(Artifacts 우선)
# =========================
def run_modules_for_drive(drive_letter: str):
    safe = norm_drive_label(drive_letter)
    drive_root = Path(f"{drive_letter}\\")
    out_root   = BASE_OUT / safe
    ensure_dir(out_root)

    artifacts_root = BASE_OUT / safe / "Artifacts" / safe
    base_dir = artifacts_root if (USE_ARTIFACTS_FOR_MODULES and artifacts_root.exists()) else drive_root

    WINDOWS = base_dir / "Windows"
    SYS32   = WINDOWS / "System32"
    USERS   = base_dir / "Users"
    LOGS    = out_root / "Logs"; ensure_dir(LOGS)

    # --- KAPE 모듈 (Evtx/PE/LE/JLE/Amcache)
    for mod in ["EvtxECmd", "PECmd", "LECmd", "JLECmd", "AmcacheParser"]:
        dest = out_root / mod
        rc = run_kape_module(base_dir, dest, mod)
        print(f"[{mod}] rc={rc}, files={has_files(dest)}")

    # --- RECmd (.reb 배치)
    dest = out_root / "RECmd"; ensure_dir(dest)
    software_hive = SYS32 / "config" / "SOFTWARE"
    system_hive   = SYS32 / "config" / "SYSTEM"

    if software_hive.exists() and (RECMD_REB_DIR / "RECmd_InstalledSoftware.reb").exists():
        run_and_log(
            [str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_InstalledSoftware.reb"),
             "-f", str(software_hive), "--csv", str(dest), "--nl"],
            LOGS / "RECmd_InstalledSoftware.log", cwd=RECMD_EXE.parent
        )
    else:
        print("[RECmd InstalledSoftware] skipped (hive or reb missing)")

    if system_hive.exists() and (RECMD_REB_DIR / "RECmd_SystemASEPs.reb").exists():
        run_and_log(
            [str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_SystemASEPs.reb"),
             "-f", str(system_hive), "--csv", str(dest), "--nl"],
            LOGS / "RECmd_SystemASEPs.log", cwd=RECMD_EXE.parent
        )
    else:
        print("[RECmd SystemASEPs] skipped (hive or reb missing)")

    if USERS.exists() and (RECMD_REB_DIR / "RECmd_UserActivity.reb").exists():
        run_and_log(
            [str(RECMD_EXE), "--bn", str(RECMD_REB_DIR / "RECmd_UserActivity.reb"),
             "-d", str(USERS), "--csv", str(dest), "--nl"],
            LOGS / "RECmd_UserActivity.log", cwd=RECMD_EXE.parent
        )
    else:
        print("[RECmd UserActivity] skipped (users or reb missing)")

    # --- SQLECmd (--hunt)  ※ 맵 오류는 로그에만 남김
    dest = out_root / "SQLECmd"; ensure_dir(dest)
    if USERS.exists():
        run_and_log(
            [str(SQLECMD_EXE), "-d", str(USERS), "--csv", str(dest), "--hunt"],
            LOGS / "SQLECmd.log", cwd=SQLECMD_EXE.parent
        )
    else:
        print("[SQLECmd] skipped (Users missing)")

    # --- SBECmd
    dest = out_root / "SBECmd"; ensure_dir(dest)
    if USERS.exists():
        run_and_log(
            [str(SBECMD_EXE), "-d", str(USERS), "--csv", str(dest), "--dedupe", "--nl"],
            LOGS / "SBECmd.log", cwd=SBECMD_EXE.parent
        )
    else:
        print("[SBECmd] skipped (Users missing)")

    # --- INDXRipper (장치 핸들 → 실패 시 $I30 폴백)
    dest = out_root / "INDXRipper"; ensure_dir(dest)
    device = r"\\.\%s" % drive_letter  # "\\.\E:"
    out_csv = dest / "indx_device.csv"
    rc = run_and_log(
        [str(INDXRIP_EXE), device, str(out_csv), "-f", "csv", "--dedup"],
        LOGS / "INDXRipper_device.log",
        cwd=INDXRIP_EXE.parent
    )
    if rc != 0 or not out_csv.exists():
        # 폴백: 복사본/원본에서 $I30들을 찾아 개별 실행
        i30s = []
        try:
            i30s += list((artifacts_root).rglob("$I30"))
        except Exception:
            pass
        try:
            i30s += list((base_dir).rglob("$I30"))
        except Exception:
            pass
        i30s = sorted(set(i30s))
        if i30s:
            for idx, p in enumerate(i30s, 1):
                out_p = dest / f"indx_{idx:04d}.csv"
                run_and_log(
                    [str(INDXRIP_EXE), str(p), str(out_p), "-f", "csv", "--dedup"],
                    LOGS / f"INDXRipper_file_{idx:04d}.log",
                    cwd=INDXRIP_EXE.parent
                )
        else:
            print("[INDXRipper] fallback: no $I30 found")

    # --- MFTECmd ($MFT/$Boot) : --rs 사용
    dest = out_root / "MFTECmd"; ensure_dir(dest)
    mft  = Path(f"{drive_letter}\\$MFT")
    boot = Path(f"{drive_letter}\\$Boot")
    if mft.exists():
        run_and_log([str(MFTECMD_EXE), "-f", str(mft), "--csv", str(dest)],
                    LOGS / "MFTECmd_$MFT.log", cwd=MFTECMD_EXE.parent)
        run_and_log([str(MFTECMD_EXE), "-f", str(mft), "--csv", str(dest), "--rs"],
                    LOGS / "MFTECmd_$MFT_rs.log", cwd=MFTECMD_EXE.parent)
    if boot.exists():
        run_and_log([str(MFTECMD_EXE), "-f", str(boot), "--csv", str(dest)],
                    LOGS / "MFTECmd_$Boot.log", cwd=MFTECMD_EXE.parent)

    # --- bstrings (권한 이슈 회피: 중간 실패 무시하고 계속)
    dest = out_root / "bstrings"; ensure_dir(dest)
    if USERS.exists():
        run_and_log([str(BSTRINGS_EXE), "-d", str(USERS), "-o", str(dest / "bstrings.txt"), "-s"],
                    LOGS / "bstrings.log", cwd=BSTRINGS_EXE.parent)
    else:
        print("[bstrings] skipped (Users missing)")

    # --- SumECmd (파일 존재할 때만)
    dest = out_root / "SumECmd"; ensure_dir(dest)
    sysid = next(USERS.rglob("SystemIdentity.mdb"), None) if USERS.exists() else None
    if sysid:
        run_and_log([str(SUMECMD_EXE), "-d", str(USERS), "--csv", str(dest)],
                    LOGS / "SumECmd.log", cwd=SUMECMD_EXE.parent)
    else:
        print("[SumECmd] skipped (SystemIdentity.mdb not found)")

    # --- WxTCmd (ActivitiesCache.db 복사본 사용)
    dest = out_root / "WxTCmd"; ensure_dir(dest)
    if USERS.exists():
        ac_list = list(USERS.rglob("ActivitiesCache.db"))
        if ac_list:
            target = sorted(ac_list, key=lambda p: p.stat().st_mtime, reverse=True)[0]
            tmp = dest / "ActivitiesCache_copy.db"
            try:
                shutil.copy2(target, tmp)
            except Exception:
                # 베스트 에포트: 원본으로 시도
                tmp = target
            run_and_log([str(WXTCMD_EXE), "-f", str(tmp), "--csv", str(dest)],
                        LOGS / "WxTCmd.log", cwd=WXTCMD_EXE.parent)
        else:
            print("[WxTCmd] skipped (ActivitiesCache.db not found)")
    else:
        print("[WxTCmd] skipped (Users missing)")

    # --- SrumECmd (KAPE 모듈로)
    dest = out_root / "SrumECmd"; ensure_dir(dest)
    rc = run_kape_module(base_dir, dest, "SrumECmd")
    print(f"[SrumECmd via KAPE] rc={rc}, files={has_files(dest)}")


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

    # 2) 타깃 복사
    print("\n=== 2) KAPE Targets(copy subset) ===")
    for d in letters:
        out_root = BASE_OUT / norm_drive_label(d)
        ensure_dir(out_root)
        rc = run_kape_targets_subset(d, out_root)
        print(f"[Targets {d}] rc={rc}")

    # 3) 모듈 파싱
    print("\n=== 3) Modules(parse hybrid) ===")
    for d in letters:
        print(f"\n--- Modules pass: {d} ---")
        run_modules_for_drive(d)

    print("\n=== Dismount ===")
    dismount_e01(device_number)
    print("[AIM] dismount issued")

if __name__ == "__main__":
    main()
