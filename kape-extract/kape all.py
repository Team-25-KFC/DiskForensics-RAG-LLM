#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Ai+Forensic – KAPE Whitelist Full Pipeline w/ Progress Logs (Win10/11, Python 3.11+)

AIM(E01) 가상 마운트
→ [Targets] 카테고리별 화이트리스트 ∩ (--tlist .) 교집합만 복사
→ [Modules] 카테고리별 매핑된 모듈만 실행(바이너리 존재/입력 존재 시)
→ 언마운트

출력 구조 (드라이브별):
  C:\Kape Output\<드라이브>\
    ├─ Artifacts\
    │   └─ <카테고리>\              # 카테고리 기준 tdest
    │       └─ <TargetName>\...     # KAPE가 타깃별로 생성
    ├─ Modules\
    │   └─ <ModuleName>\
    │       └─ <카테고리>\*.csv     # 모듈별/카테고리별 CSV
    └─ Logs\
        ├─ Targets\
        │   ├─ success\*.log
        │   └─ fail\*.log
        └─ Modules\
            ├─ success\*.log
            └─ fail\*.log

콘솔 진행 로그 예시:
- [START] AIM 가상 마운트 시작 …
- [MOUNT] NTFS 볼륨 2개 발견: I:, K:
- [DRIVE I] 타깃 실행 시작(카테고리 13개) … → 완료
- [DRIVE I] 모듈 실행 시작(카테고리 13개) … → 완료
- [DRIVE K] … (반복)
- [DONE] 전체 완료
"""

import os, sys, time, re, subprocess, shutil
from pathlib import Path
from datetime import datetime

# ===========================
# 사용자 설정
# ===========================
AIM_EXE   = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_PATH  = r"H:\Laptop\Laptop.E01"
KAPE_EXE  = r"D:\KAPE\kape.exe"

# 스크린샷 기준 bin 레이아웃(D: 경로) — 폴더/하위폴더에 exe가 섞여있음
MODULES_BIN = Path(r"D:\KAPE\Modules\bin")

BASE_OUT = Path(r"D:\Kape Output")
BASE_OUT.mkdir(parents=True, exist_ok=True)

MOUNT_STABILIZE_SEC = 15
KAPE_TIMEOUT_SEC = 60 * 60

# ===========================
# 화이트리스트 (카테고리 → 타깃들)
# ===========================
WL = {
    "$NTFS": ["$MFT", "$MFTMirr", "$LogFile", "$Boot", "$SDS", "$T", "$J"],
    "레지스트리〔USB 포함 흡수〕": ["RegistryHives", "RegistryHivesSystem", "RegistryHivesUser", "RegistryHivesOther", "GroupPolicy", "USBDevicesLogs"],
    "이벤트로그": ["EventLogs", "EventTraceLogs", "EventTranscriptDB", "ApplicationEvents", "BITS", "CBS", "WindowsPowerDiagnostics",
                 "WindowsTelemetryDiagnosticsLegacy", "WindowsFirewall", "WBEM", "WER", "WindowsIndexSearch", "WindowsNotificationsDB", "WindowsOSUpgradeArtifacts"],
    "실행흔적": ["Amcache", "LNKFilesAndJumpLists", "PowerShellConsole", "RDPLogs"],
    "캐시": ["Prefetch", "RecentFileCache", "Syscache", "ThumbCache", "JavaWebCache", "OfficeDocumentCache"],
    "시작프로그램": ["StartupFolders", "StartupInfo", "ScheduledTasks", "SDB(Shim DB)"],
    "타임라인 - 활동기록": ["SRUM", "WindowsTimeline", "OfficeAutosave", "OfficeDiagnostics"],
    "브라우저": ["Chrome", "ChromeExtensions", "ChromeFileSystem", "Edge", "EdgeChromium", "InternetExplorer"],
    "클라우드": ["OneDrive_Metadata", "OneDrive_UserFiles"],
    "APP": ["OutlookPSTOST", "MicrosoftTeams", "MicrosoftToDo", "WindowsYourPhone", "Slack", "Telegram", "Discord", "Zoom",
            "MicrosoftOneNote", "MicrosoftStickyNotes", "Notepad++", "VLC Media Player"],
    "보안": ["Antivirus", "WindowsDefender", "WinDefendDetectionHist", "ManageEngineLogs", "Avast", "AVG", "AviraAVLogs", "Bitdefender",
            "Combofix", "Emsisoft", "ESET", "FSecure", "Malwarebytes", "McAfee", "McAfee_ePO", "RogueKiller", "SecureAge",
            "SentinelOne", "Sophos", "SUPERAntiSpyware", "TotalAV", "VIPRE", "Webroot"],
    "휴지통": ["RecycleBin_DataFiles", "RecycleBin_InfoFiles"],
    "인증서": ["CertUtil"],
}

# ===========================
# 카테고리 → 모듈 매핑 (KAPE 모듈명)
# ※ 모듈 바이너리 존재하면 실행. 미존재 시 자동 스킵.
# ===========================
CAT2MODULES = {
    "$NTFS": [
        "MFTECmd_$MFT", "MFTECmd_$Boot", "MFTECmd_$MFT_FileListing",
        "MFTECmd_$MFT_ProcessMFTSlack", "MFTECmd_$MFT_DumpResidentFiles",
        "MFTECmd_$J", "NTFSLogTracker_$J", "NTFSLogTracker_$LogFile", "INDXRipper"
    ],
    "레지스트리〔USB 포함 흡수〕": [
        # 반드시 포함(요구사항)
        "RECmd_BasicSystemInfo", "RECmd_BCDBootVolume", "RECmd_InstalledSoftware",
        "RECmd_RegistryASEPs", "RECmd_SoftwareASEPs", "RECmd_SoftwareClassesASEPs",
        "RECmd_SoftwareWow6432ASEPs", "RECmd_SystemASEPs", "RECmd_UserActivity",
        "RECmd_UserClassesASEPs", "RECmd_AllRegExecutablesFoundOrRun", 
        "RECmd_RECmd_Batch_MC", "RECmd_Kroll"
    ],
    "이벤트로그": ["EvtxECmd"],
    "실행흔적": ["AmcacheParser", "LECmd", "JLECmd", "PECmd"],  # RDPLogs는 EvtxECmd로도 일부 커버
    "캐시": ["PECmd", "RecentFileCacheParser", "SBECmd"],
    "시작프로그램": ["RECmd_RegistryASEPs", "RECmd_SoftwareASEPs", "RECmd_SystemASEPs"],
    "타임라인 - 활동기록": ["SrumECmd", "WxTCmd"],
    "브라우저": ["SQLECmd", "SBECmd"],
    "클라우드": ["SQLECmd"],  # OneDrive DB 등
    "APP": ["SQLECmd", "SBECmd"],
    "보안": ["SQLECmd", "SBECmd", "RECmd_BasicSystemInfo"],
    "휴지통": ["RBCmd"],
    "인증서": ["CertUtil"],  # KAPE 모듈명이 동일
}

# ===========================
# 모듈 실행에 필요한 EXE 이름 맵 (KAPE 모듈명 → exe 파일명 후보 리스트)
# ===========================
MODULE_EXE_HINTS = {
    "MFTECmd": ["MFTECmd.exe"],
    "NTFSLogTracker": ["NTFS_Log_Tracker_CMD.exe"],
    "INDXRipper": ["INDXRipper.exe"],
    "EvtxECmd": ["EvtxECmd.exe"],
    "RECmd": ["RECmd.exe"],
    "LECmd": ["LECmd.exe"],
    "JLECmd": ["JLECmd.exe"],
    "PECmd": ["PECmd.exe"],
    "RecentFileCacheParser": ["RecentFileCacheParser.exe"],
    "SBECmd": ["SBECmd.exe"],
    "SrumECmd": ["SrumECmd.exe"],
    "SQLECmd": ["SQLECmd.exe"],
    "WxTCmd": ["WxTCmd.exe"],
    "RBCmd": ["RBCmd.exe"],
    "AmcacheParser": ["AmcacheParser.exe"],
    "AppCompatCacheParser": ["AppCompatCacheParser.exe"],
    "CertUtil": ["CertUtil.exe"],  # 시스템 내장도 허용
}

# ---------------------------
# 콘솔 진행 로그
# ---------------------------
def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def banner(msg: str):
    print(f"[{ts()}] {msg}")

# ===========================
# PowerShell 유틸
# ===========================
def run_ps(cmd: str):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True)

def ps_lines(cp):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

# ===========================
# 파일명 정규화(로그용)  ★ PermissionError 방지 패치
# ===========================
INVALID_CHARS = r'<>:"/\|?*'

def sanitize_name(s: str) -> str:
    t = s.replace(":", "-")
    for ch in INVALID_CHARS:
        t = t.replace(ch, "-")
    t = t.strip().rstrip(".")
    return t or "log"

# ===========================
# AIM 마운트 / 언마운트
# ===========================
def mount_e01():
    banner("AIM 가상 마운트 시작 …")
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
        banner(f"AIM 마운트 완료: Device={device_number}, PhysicalDrive={disk_number}")
        return disk_number, device_number
    except Exception as e:
        banner(f"[ERROR] AIM 마운트 실패: {e}")
        return None, None

def dismount_e01(device_number=None):
    banner("AIM 언마운트 시도 …")
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        banner("AIM 언마운트 완료.")
    except Exception as e:
        banner(f"[ERROR] AIM 언마운트 실패: {e}")

# ===========================
# 볼륨 유틸
# ===========================
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

# ===========================
# KAPE 타깃/모듈 도우미
# ===========================
def get_available_targets() -> set[str]:
    try:
        proc = subprocess.run([KAPE_EXE, "--tlist", "."], capture_output=True, text=True, timeout=120)
        text = (proc.stdout or "") + (proc.stderr or "")
        names = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Target: "):
                name = line[len("Target: "):].strip()
                if " (" in name:
                    name = name.split(" (", 1)[0].strip()
                names.append(name)
        return set(names)
    except Exception as e:
        banner(f"[ERROR] --tlist 실패: {e}")
        return set()

def dir_has_files(p: Path) -> bool:
    if not p.exists():
        return False
    for _root, _dirs, files in os.walk(p):
        if files:
            return True
    return False

def write_log(log_dir: Path, name: str, ok: bool, lines: list[str]):
    sub = log_dir / ("success" if ok else "fail")
    sub.mkdir(parents=True, exist_ok=True)
    safe = sanitize_name(name)
    out = sub / f"{safe}.log"
    with open(out, "w", encoding="utf-8", errors="ignore") as f:
        for ln in lines:
            f.write(ln.rstrip() + "\n")

# ===========================
# 타깃 실행 (카테고리 단위)
# ===========================
def run_targets_for_category(letter: str, category: str, targets: list[str],
                             avail_targets: set[str], artifacts_root: Path, logs_root: Path) -> bool:
    resolved = [t for t in targets if t in avail_targets]
    if not resolved:
        write_log(logs_root / "Targets", f"{letter[0]}_{category}_targets",
                  False, [f"[WARN] No targets resolved for {category}"])
        banner(f"[DRIVE {letter}] {category}: 실행할 타깃 없음(교집합 0)")
        return False

    tdest = artifacts_root / category
    tdest.mkdir(parents=True, exist_ok=True)
    cmd = [
        KAPE_EXE,
        "--tsource", letter,
        "--tdest", str(tdest),
        "--target", ",".join(resolved),
        "--vss", "false"
    ]
    banner(f"[DRIVE {letter}] Targets ▶ {category} ( {', '.join(resolved)} )")
    lines = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        for line in proc.stdout:
            s = line.strip()
            if s:
                lines.append(s)
        rc = proc.wait(timeout=KAPE_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        lines.append("[ERROR] KAPE targets timeout")
        write_log(logs_root / "Targets", f"{letter[0]}_{category}_targets", False, lines)
        banner(f"[DRIVE {letter}] Targets ✖ {category} (timeout)")
        return False
    except Exception as e:
        lines.append(f"[ERROR] {e}")
        write_log(logs_root / "Targets", f"{letter[0]}_{category}_targets", False, lines)
        banner(f"[DRIVE {letter}] Targets ✖ {category} ({e})")
        return False

    ok_rc = (rc == 0)
    ok_files = dir_has_files(tdest)
    ok = ok_rc and ok_files
    if not ok_files:
        lines.append(f"[SKIP] No files copied under: {tdest}")
        banner(f"[DRIVE {letter}] Targets △ {category} (결과 파일 없음)")
    else:
        banner(f"[DRIVE {letter}] Targets ✔ {category}")
    write_log(logs_root / "Targets", f"{letter[0]}_{category}_targets", ok, lines)
    return ok

# ===========================
# 모듈 실행 (카테고리 단위)
# ===========================
MODULE_EXE_HINTS_LOWER = {k.lower(): v for k, v in MODULE_EXE_HINTS.items()}

def _tool_basename_from_module(module_name: str) -> str:
    return module_name.split("_")[0] if "_" in module_name else module_name

def exe_exists_in_bin(tool_base: str) -> bool:
    hints = MODULE_EXE_HINTS_LOWER.get(tool_base.lower(), [])
    if not hints:
        return True  # 힌트 없으면 검사 생략
    for hint in hints:
        for p in MODULES_BIN.rglob(hint):
            if p.is_file():
                return True
    if tool_base.lower() == "certutil":
        try:
            cp = subprocess.run(["where", "certutil"], capture_output=True, text=True)
            if cp.returncode == 0 and cp.stdout.strip():
                return True
        except Exception:
            pass
    return False

def run_modules_for_category(letter: str, category: str, modules: list[str],
                             artifacts_root: Path, modules_root: Path, logs_root: Path):
    msource = artifacts_root / category
    if not dir_has_files(msource):
        write_log(logs_root / "Modules", f"{letter[0]}_{category}_modules", False,
                  [f"[SKIP] No inputs found in {msource}"])
        banner(f"[DRIVE {letter}] Modules △ {category} (입력 없음, 스킵)")
        return

    for module_name in modules:
        tool_base = _tool_basename_from_module(module_name)
        if tool_base.startswith("NTFSLogTracker"):
            tool_base = "NTFSLogTracker"

        if not exe_exists_in_bin(tool_base):
            write_log(logs_root / "Modules", f"{letter[0]}_{category}_{module_name}", False,
                      [f"[SKIP] Missing tool exe for {tool_base}"])
            banner(f"[DRIVE {letter}] Module △ {module_name} (실행파일 없음, 스킵)")
            continue

        mdest = modules_root / module_name / category
        mdest.mkdir(parents=True, exist_ok=True)

        cmd = [
            KAPE_EXE,
            "--msource", str(msource),
            "--mdest", str(mdest),
            "--module", module_name,
            "--mef", "csv",
            "--vss", "false"
        ]

        banner(f"[DRIVE {letter}] Module ▶ {module_name} @ {category}")
        lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert proc.stdout
            for line in proc.stdout:
                s = line.strip()
                if s:
                    lines.append(s)
            rc = proc.wait(timeout=KAPE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            lines.append("[ERROR] KAPE module timeout")
            write_log(logs_root / "Modules", f"{letter[0]}_{category}_{module_name}", False, lines)
            banner(f"[DRIVE {letter}] Module ✖ {module_name} (timeout)")
            continue
        except Exception as e:
            lines.append(f"[ERROR] {e}")
            write_log(logs_root / "Modules", f"{letter[0]}_{category}_{module_name}", False, lines)
            banner(f"[DRIVE {letter}] Module ✖ {module_name} ({e})")
            continue

        ok_rc = (rc == 0)
        ok_files = dir_has_files(mdest)
        ok = ok_rc and ok_files
        if not ok_files:
            lines.append(f"[SKIP] No CSV produced under: {mdest}")
            banner(f"[DRIVE {letter}] Module △ {module_name} (CSV 없음)")
        else:
            banner(f"[DRIVE {letter}] Module ✔ {module_name}")
        write_log(logs_root / "Modules", f"{letter[0]}_{category}_{module_name}", ok, lines)

# ===========================
# MAIN
# ===========================
def main():
    for p in (AIM_EXE, KAPE_EXE, E01_PATH):
        if not os.path.exists(p):
            print(f"[ERROR] Missing path: {p}")
            sys.exit(2)

    banner("KAPE 타깃 리스트 수집 중 …")
    avail_targets = get_available_targets()
    banner(f"KAPE 타깃 {len(avail_targets)}개 확보")

    disk, dev = mount_e01()
    if disk is None:
        print("[ERROR] Mount failed.")
        sys.exit(5)

    vols = get_ntfs_volumes(disk)
    letters = []
    for v in vols:
        lt = get_letter_for_volume(v)
        if lt:
            letters.append(lt)

    if not letters:
        dismount_e01(dev)
        print("[ERROR] No NTFS volumes.")
        sys.exit(6)

    banner(f"[MOUNT] NTFS 볼륨 {len(letters)}개: {', '.join(letters)}")

    for letter in letters:
        drive_root     = BASE_OUT / f"{letter[0]}"
        artifacts_root = drive_root / "Artifacts"
        modules_root   = drive_root / "Modules"
        logs_root      = drive_root / "Logs"
        (logs_root / "Targets" / "success").mkdir(parents=True, exist_ok=True)
        (logs_root / "Targets" / "fail").mkdir(parents=True, exist_ok=True)
        (logs_root / "Modules" / "success").mkdir(parents=True, exist_ok=True)
        (logs_root / "Modules" / "fail").mkdir(parents=True, exist_ok=True)

        banner(f"[DRIVE {letter}] 처리 시작 → 출력 루트: {drive_root}")

        # 1) 카테고리별 타깃 실행
        banner(f"[DRIVE {letter}] 타깃 실행 시작 (카테고리 {len(WL)}개)")
        for category, targets in WL.items():
            run_targets_for_category(letter, category, targets, avail_targets, artifacts_root, logs_root)
        banner(f"[DRIVE {letter}] 타깃 실행 완료")

        # 2) 카테고리별 모듈 실행
        banner(f"[DRIVE {letter}] 모듈 실행 시작 (카테고리 {len(CAT2MODULES)}개)")
        for category, modules in CAT2MODULES.items():
            run_modules_for_category(letter, category, modules, artifacts_root, modules_root, logs_root)
        banner(f"[DRIVE {letter}] 모듈 실행 완료")

        banner(f"[DRIVE {letter}] 처리 종료")

    dismount_e01(dev)
    banner("[DONE] 전체 완료 → 출력 경로: " + str(BASE_OUT))

if __name__ == "__main__":
    main()
