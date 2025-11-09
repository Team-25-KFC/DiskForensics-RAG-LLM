#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
artifacts.py — Target-only 복사 워커 (Win10/11)
- 오케스트레이터(main.py)가 마운트/드라이브 결정을 끝낸 뒤 호출
- 화이트리스트(Target allowlist)만 1패스로 복사
- 모듈 실행/언마운트는 하지 않음
출력 구조:
  <BASE_OUT>\<드라이브>\Artifacts\*      (KAPE Target 복사본)
  <BASE_OUT>\<드라이브>\Logs\targets_copy.log
"""

import subprocess
from pathlib import Path
from typing import List

# ── Target allowlist (프로젝트 규칙) ───────────────────────────────
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
    "SRUM", "WindowsTimeline", "OfficeDiagnostics", "OfficeAutosave",
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

# ── 경로 유틸 ──────────────────────────────────────────────────────
def _drive_root(dl: str) -> str:
    """'E:' -> 'E:\\'"""
    return f"{dl}\\"

def _artifacts_root(base_out: Path, dl: str) -> Path:
    """D:\Kape Output\E\Artifacts"""
    return base_out / dl[0] / "Artifacts"

def _logs_dir(base_out: Path, dl: str) -> Path:
    d = base_out / dl[0] / "Logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _marker(base_out: Path, dl: str) -> Path:
    return _artifacts_root(base_out, dl) / ".targets_subset_done"

# ── KAPE 실행 ──────────────────────────────────────────────────────
def _run_kape_target_copy(kape_exe: Path, dl: str, targets: List[str],
                          dest: Path, timeout_sec: int, log_path: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    if not targets:
        return 0

    cmd = [
        str(kape_exe),
        "--tsource", _drive_root(dl),   # 예: E:\
        "--tdest",   str(dest),         # 예: D:\Kape Output\E\Artifacts
        "--target",  ",".join(targets),
        "--vss",     "false",
    ]

    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        try:
            for line in proc.stdout:
                lf.write(line.rstrip() + "\n")
            rc = proc.wait(timeout=timeout_sec if timeout_sec > 0 else None)
            return rc
        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9

# ── 엔트리포인트 ──────────────────────────────────────────────────
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    main.py에서 호출:
      - drive_letters: ['E:', 'I:', ...]
      - unmount_callback: AIM 언마운트 콜백 (여기서는 '절대' 호출하지 않음)
      - cfg: {"BASE_OUT": Path, "KAPE_EXE": Path, "PROC_TIMEOUT_SEC": int}
    반환: False (언마운트는 메인에서 수행)
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path  = cfg["KAPE_EXE"]
    TIMEOUT:  int   = int(cfg["PROC_TIMEOUT_SEC"])

    if not KAPE_EXE.exists():
        print(f"[FATAL] KAPE 실행 파일 없음: {KAPE_EXE}")
        return False

    try:
        for dl in drive_letters:
            dest   = _artifacts_root(BASE_OUT, dl)
            logs   = _logs_dir(BASE_OUT, dl)
            mark   = _marker(BASE_OUT, dl)
            log_fp = logs / "targets_copy.log"

            if mark.exists():
                print(f"[SKIP] {dl} target-only: 이미 복사 완료 ({mark})")
                continue

            print(f"[RUN ] {dl} target-only: {len(TARGET_SUBSET)}개 타깃 복사 → {dest}")
            rc = _run_kape_target_copy(KAPE_EXE, dl, TARGET_SUBSET, dest, TIMEOUT, log_fp)

            if rc == 0:
                try:
                    mark.write_text("done", encoding="utf-8")
                except Exception:
                    pass
                print(f"[OK  ] {dl} target-only: 복사 완료")
            else:
                print(f"[FAIL] {dl} target-only: rc={rc} (로그 참조: {log_fp})")

        # 언마운트는 메인에서 하도록 False 반환
        return False

    except Exception as e:
        print(f"[FATAL] artifacts(target-only) 실패: {e}")
        return False
