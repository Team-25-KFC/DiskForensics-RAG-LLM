#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EvtxECmd CSV를 입력으로 받아
type / time / description / tags 형식으로 변환하는 이벤트 로그 태깅 모듈.

✅ 요구 반영:
- run() 같은 “외부 인자 필요 함수” 없이, Ctrl+F5(=python 파일 실행)로 바로 동작
- D:~Z: 아래 "Kape Output" 폴더를 자동 탐색해서 EvtxECmd *_Output.csv 자동 처리
- 태그 prefix는 8개만 사용:
  ARTIFACT_ / EVENT_ / AREA_ / SEC_ / FORMAT_ / ACT_ / TIME_ / STATE_
"""

import csv
import os
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Any


# ============================================================
# 0) 자동 탐색 기본 설정 (인자 없이 F5 실행)
# ============================================================

# 1차 필터: 파일명 패턴으로 후보를 좁힘 (EvtxECmd Output CSV)
# 예) Security_EvtxECmd_Output.csv, System_EvtxECmd_Output.csv
TARGET_GLOB = "*EvtxECmd*_Output.csv"

# 출력 컬럼
OUT_FIELDNAMES = ["type", "time", "description", "tags"]

# 시간 태그 버킷
DELTA_RECENT = timedelta(days=1)
DELTA_WEEK = timedelta(days=7)
DELTA_MONTH = timedelta(days=30)

# 확장자 분류(이벤트로그에서도 path/image에 파일명이 들어올 수 있어 유지)
EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".com", ".scr"}
SCRIPT_EXTS = {".ps1", ".bat", ".vbs", ".js", ".py", ".cmd", ".hta"}
DOCUMENT_EXTS = {".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt", ".hwp"}
SPREADSHEET_EXTS = {".xls", ".xlsx", ".csv"}
PRESENTATION_EXTS = {".ppt", ".pptx"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg"}
VIDEO_EXTS = {".mp4", ".avi", ".mkv", ".mov", ".wmv"}
AUDIO_EXTS = {".mp3", ".wav", ".flac", ".wma", ".m4a"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}
DATABASE_EXTS = {".db", ".sqlite", ".accdb", ".mdb"}
LOG_EXTS = {".evtx", ".evt", ".log"}
CONFIG_EXTS = {".ini", ".xml", ".json", ".yaml", ".yml", ".conf", ".cfg"}
REGISTRY_EXTS = {".dat", ".hve", ".reg"}
EMAIL_EXTS = {".pst", ".ost", ".msg", ".eml"}
SHORTCUT_EXTS = {".lnk", ".url"}

SUSPICIOUS_NAME_KEYWORDS = [
    "crack", "keygen", "mimikatz", "purelogs", "vidar",
    "miner", "xmrig", "wannacry", "notpetya", "backdoor",
    "cobalt", "meterpreter", "hacktool", "dump", "payload", "shell",
]


# ============================================================
# 1) 공통 유틸
# ============================================================

def safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def get_first_nonempty(row: Dict[str, Any], candidates: List[str]) -> str:
    for key in candidates:
        v = row.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def add_tag(tags: Set[str], value: Optional[str]) -> None:
    if value:
        tags.add(value)


def parse_time(timestr: str) -> Optional[datetime]:
    """
    EvtxECmd TimeCreated/TimeCreatedUtc 파싱용.
    반환값은 UTC tzinfo를 가진 datetime.

    지원:
      - 2025-12-04 02:03:31.709449
      - 2025-12-04 02:03:31.7094494 (7자리 micro → 6자리 절단)
      - 2025-12-04T02:03:31.7094494Z
      - 2025-12-04 02:03:31
    """
    if not timestr:
        return None
    s = str(timestr).strip()
    if not s:
        return None

    # 끝의 ' UTC' 또는 'Z' 제거
    s = re.sub(r"\s*(UTC|Z)$", "", s, flags=re.IGNORECASE)

    # 'T' → ' '
    s = s.replace("T", " ")

    # 7자리 마이크로초 → 6자리로 절단
    m = re.search(r"\.(\d{6,7})$", s)
    if m:
        micro = m.group(1)
        if len(micro) == 7:
            s = s.replace("." + micro, "." + micro[:6])

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ============================================================
# 2) “분석 기준시간(now)” 자동 추출 (파일명 timestamp)
# ============================================================

_TIME_PATTERNS = [
    # 2025-12-05T05_08_01_0813195_ConsoleLog.txt → 2025-12-05T05_08_01
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2})"), "%Y-%m-%dT%H_%M_%S"),
    # 20251205045710_EvtxECmd_Module.txt → 20251205045710
    (re.compile(r"(\d{14})"), "%Y%m%d%H%M%S"),
]


def _parse_marker_time_from_name(name: str) -> Optional[datetime]:
    for pattern, fmt in _TIME_PATTERNS:
        m = pattern.search(name)
        if not m:
            continue
        ts = m.group(1)
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _get_analysis_time_for_case(case_root: Path) -> datetime:
    """
    case_root (예: X:\\Kape Output\\<CASE>)에서
    1) *_Module.txt / *ConsoleLog*.txt
    2) 없으면 *.txt 전체
    를 mtime 최신순으로 보며, 파일명에서 timestamp 파싱 성공 시 그 값을 now로 사용.
    실패하면 현재 UTC.
    """
    candidates: List[Path] = []
    try:
        candidates = [p for p in case_root.rglob("*_Module.txt") if p.is_file()]
        candidates += [p for p in case_root.rglob("*ConsoleLog*.txt") if p.is_file()]
    except Exception:
        candidates = []

    if not candidates:
        try:
            candidates = [p for p in case_root.rglob("*.txt") if p.is_file()]
        except Exception:
            candidates = []

    if not candidates:
        return datetime.now(timezone.utc)

    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)

    for p in candidates:
        dt = _parse_marker_time_from_name(p.name)
        if dt is not None:
            return dt

    return datetime.now(timezone.utc)


# ============================================================
# 3) 태깅 로직 (8개 prefix만 사용)
# ============================================================

def tag_artifact(row: Dict[str, Any], tags: Set[str]) -> None:
    add_tag(tags, "ARTIFACT_EVENT_LOG")

    fs_path = get_first_nonempty(
        row,
        ["NewProcessName", "Image", "TargetFilename", "ObjectName", "Path", "FilePath",
         "DestinationFilename", "SourceFilename"],
    )
    if fs_path:
        add_tag(tags, "ARTIFACT_FILE")

    reg_text = " ".join(
        [
            get_first_nonempty(row, ["ObjectName", "TargetObject", "TargetFilename", "Path"]),
            get_first_nonempty(row, ["Message", "Description", "EventMessage", "Payload"]),
        ]
    ).upper()
    if any(x in reg_text for x in ("HKLM\\", "HKCU\\", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER")):
        add_tag(tags, "ARTIFACT_REGISTRY")

    channel = str(row.get("Channel") or "")
    provider = str(row.get("ProviderName") or row.get("Provider") or "")
    msg = get_first_nonempty(row, ["Message", "Description", "EventMessage", "Payload"])

    if (
        "microsoft-windows-taskscheduler/operational" in channel.lower()
        or "taskscheduler" in provider.lower()
        or "scheduled task" in msg.lower()
    ):
        add_tag(tags, "ARTIFACT_SCHEDULED_TASK")

    if "microsoft-windows-wmi-activity/operational" in channel.lower() or "wmi" in provider.lower():
        add_tag(tags, "ARTIFACT_WMI")


def tag_event(row: Dict[str, Any], tags: Set[str]) -> None:
    """
    EVENT_ 태그는 반드시 아래 9개만 사용:
      EVENT_CREATE / EVENT_MODIFY / EVENT_DELETE / EVENT_RENAME / EVENT_MOVE / EVENT_COPY /
      EVENT_RECOVERED / EVENT_ACCESSED / EVENT_EXECUTED
    """
    event_id = safe_int(row.get("EventID"))
    if event_id is None:
        event_id = safe_int(row.get("EventId"))

    channel = str(row.get("Channel") or "").lower()
    provider = str(row.get("ProviderName") or row.get("Provider") or "").lower()
    msg = get_first_nonempty(row, ["Message", "Description", "EventMessage", "Payload"])
    msg_l = msg.lower()

    is_security = (channel == "security")
    is_system = (channel == "system")
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_defender = "microsoft-windows-windows defender" in channel or "defender" in provider
    is_powershell = "microsoft-windows-powershell/operational" in channel
    is_wmi = "microsoft-windows-wmi-activity/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel

    if is_security and event_id is not None:
        if event_id in (4624, 4625, 4634, 4647, 4648,
                        4768, 4769, 4770, 4771, 4772, 4776, 4778, 4779):
            add_tag(tags, "EVENT_ACCESSED")

        if event_id == 4688:
            add_tag(tags, "EVENT_CREATE")
            add_tag(tags, "EVENT_EXECUTED")
        elif event_id == 4689:
            add_tag(tags, "EVENT_DELETE")

        if event_id in (4720,):
            add_tag(tags, "EVENT_CREATE")
        if event_id in (4722, 4723, 4724, 4725, 4727, 4738, 4767, 4740):
            add_tag(tags, "EVENT_MODIFY")
        if event_id in (4726,):
            add_tag(tags, "EVENT_DELETE")

        if event_id in (4728, 4729, 4732, 4733, 4735, 4737, 4756, 4757, 4758, 4761, 4762):
            add_tag(tags, "EVENT_MODIFY")

        if event_id in (4672, 4673, 4674):
            add_tag(tags, "EVENT_ACCESSED")

        if event_id in (4719, 4739, 4902, 4904, 4905, 4907):
            add_tag(tags, "EVENT_MODIFY")

        if event_id in (4663, 4656, 4658, 4662, 4670):
            add_tag(tags, "EVENT_ACCESSED")
        if event_id == 4660:
            add_tag(tags, "EVENT_DELETE")
        if event_id == 4657:
            add_tag(tags, "EVENT_MODIFY")

        if event_id == 4697:
            add_tag(tags, "EVENT_CREATE")
        if event_id == 4698:
            add_tag(tags, "EVENT_CREATE")
        if event_id == 4699:
            add_tag(tags, "EVENT_DELETE")
        if event_id == 4702:
            add_tag(tags, "EVENT_MODIFY")

        if event_id == 1102:
            add_tag(tags, "EVENT_DELETE")

        if event_id in (5154, 5155, 5156, 5157):
            add_tag(tags, "EVENT_ACCESSED")

        if event_id in (5140, 5145):
            add_tag(tags, "EVENT_ACCESSED")

    if is_system and event_id is not None:
        if event_id in (7000, 7001, 7035, 7036):
            add_tag(tags, "EVENT_EXECUTED")
        if event_id == 7040:
            add_tag(tags, "EVENT_MODIFY")
        if event_id == 7045:
            add_tag(tags, "EVENT_CREATE")
        if event_id in (6005, 6006, 6008, 6009):
            add_tag(tags, "EVENT_MODIFY")

    if is_tasksched and event_id is not None:
        if event_id in (100, 101, 102, 107, 108, 110, 111, 118, 119, 129, 200):
            add_tag(tags, "EVENT_EXECUTED")
        if event_id == 106:
            add_tag(tags, "EVENT_CREATE")
        if event_id == 140:
            add_tag(tags, "EVENT_MODIFY")
        if event_id == 141:
            add_tag(tags, "EVENT_DELETE")
        if event_id == 142:
            add_tag(tags, "EVENT_MODIFY")

    if is_defender and event_id is not None:
        if event_id == 1116:
            add_tag(tags, "EVENT_ACCESSED")
        if event_id in (5000, 5001, 5004, 5007, 5010):
            add_tag(tags, "EVENT_MODIFY")

    if is_powershell and event_id is not None:
        if event_id in (4103, 4104, 4105, 4106):
            add_tag(tags, "EVENT_EXECUTED")

    if is_wmi and event_id is not None:
        if event_id in (5857, 5858, 5859, 5860, 5861):
            add_tag(tags, "EVENT_EXECUTED")

    if is_bits and event_id is not None:
        if event_id in (1, 2, 3, 4, 5, 59, 60, 61, 63):
            add_tag(tags, "EVENT_ACCESSED")

    # 메시지 기반 fallback
    if "created" in msg_l:
        add_tag(tags, "EVENT_CREATE")
    if "modified" in msg_l or "changed" in msg_l:
        add_tag(tags, "EVENT_MODIFY")
    if "deleted" in msg_l or "removed" in msg_l:
        add_tag(tags, "EVENT_DELETE")
    if "renamed" in msg_l:
        add_tag(tags, "EVENT_RENAME")
    if "moved" in msg_l:
        add_tag(tags, "EVENT_MOVE")
    if "copied" in msg_l:
        add_tag(tags, "EVENT_COPY")
    if "recovered" in msg_l or "carved" in msg_l:
        add_tag(tags, "EVENT_RECOVERED")
    if "accessed" in msg_l or "logged on" in msg_l:
        add_tag(tags, "EVENT_ACCESSED")
    if "started" in msg_l or "executed" in msg_l:
        add_tag(tags, "EVENT_EXECUTED")

    if not any(t.startswith("EVENT_") for t in tags):
        add_tag(tags, "EVENT_ACCESSED")


def tag_area(row: Dict[str, Any], tags: Set[str]) -> None:
    path = get_first_nonempty(row, ["NewProcessName", "Image", "Path", "TargetFilename", "ObjectName"])
    if not path:
        return

    lower = path.lower().replace("/", "\\")

    if "\\windows\\system32" in lower or lower.startswith("c:\\windows\\system32"):
        add_tag(tags, "AREA_SYSTEM32")
    elif "\\windows" in lower:
        add_tag(tags, "AREA_WINDOWS")

    if "\\users\\" in lower:
        if "\\desktop\\" in lower:
            add_tag(tags, "AREA_USER_DESKTOP")
        if "\\documents\\" in lower:
            add_tag(tags, "AREA_USER_DOCUMENTS")
        if "\\downloads\\" in lower:
            add_tag(tags, "AREA_USER_DOWNLOADS")
        if "\\recent\\" in lower:
            add_tag(tags, "AREA_USER_RECENT")
        if "\\appdata\\local\\" in lower:
            add_tag(tags, "AREA_APPDATA_LOCAL")
        if "\\appdata\\roaming\\" in lower:
            add_tag(tags, "AREA_APPDATA_ROAMING")
        if "\\appdata\\locallow\\" in lower:
            add_tag(tags, "AREA_APPDATA_LOCALLOW")

    if "\\program files" in lower:
        add_tag(tags, "AREA_PROGRAMFILES")
    if "\\programdata\\" in lower:
        add_tag(tags, "AREA_PROGRAMDATA")

    if "\\windows\\temp" in lower or "\\temp\\" in lower:
        add_tag(tags, "AREA_TEMP")

    if "\\microsoft\\windows\\start menu\\programs\\startup" in lower:
        add_tag(tags, "AREA_STARTUP")

    if "\\$recycle.bin" in lower:
        add_tag(tags, "AREA_RECYCLE_BIN")
    if "system volume information" in lower:
        add_tag(tags, "AREA_VSS")
    if lower.startswith("\\\\"):
        add_tag(tags, "AREA_NETWORK_SHARE")
    if re.match(r"^[a-z]:\\", lower) and lower[0].upper() in "DEFGHIJKLMNOPQRSTUVWXYZ":
        add_tag(tags, "AREA_EXTERNAL_DRIVE")


def tag_format(row: Dict[str, Any], tags: Set[str]) -> None:
    path = get_first_nonempty(row, ["NewProcessName", "Image", "TargetFilename", "ObjectName"])
    if not path:
        return
    _, ext = os.path.splitext(path.lower())

    if ext in DOCUMENT_EXTS:
        add_tag(tags, "FORMAT_DOCUMENT")
    elif ext in SPREADSHEET_EXTS:
        add_tag(tags, "FORMAT_SPREADSHEET")
    elif ext in PRESENTATION_EXTS:
        add_tag(tags, "FORMAT_PRESENTATION")
    elif ext in IMAGE_EXTS:
        add_tag(tags, "FORMAT_IMAGE")
    elif ext in VIDEO_EXTS:
        add_tag(tags, "FORMAT_VIDEO")
    elif ext in AUDIO_EXTS:
        add_tag(tags, "FORMAT_AUDIO")
    elif ext in ARCHIVE_EXTS:
        add_tag(tags, "FORMAT_ARCHIVE")
    elif ext in EXECUTABLE_EXTS:
        add_tag(tags, "FORMAT_EXECUTABLE")
    elif ext in SCRIPT_EXTS:
        add_tag(tags, "FORMAT_SCRIPT")
    elif ext in DATABASE_EXTS:
        add_tag(tags, "FORMAT_DATABASE")
    elif ext in LOG_EXTS:
        add_tag(tags, "FORMAT_LOG")
    elif ext in CONFIG_EXTS:
        add_tag(tags, "FORMAT_CONFIG")
    elif ext in REGISTRY_EXTS:
        add_tag(tags, "FORMAT_REGISTRY")
    elif ext in EMAIL_EXTS:
        add_tag(tags, "FORMAT_EMAIL")
    elif ext in SHORTCUT_EXTS:
        add_tag(tags, "FORMAT_SHORTCUT")


def tag_security(row: Dict[str, Any], tags: Set[str]) -> None:
    event_id = safe_int(row.get("EventID"))
    if event_id is None:
        event_id = safe_int(row.get("EventId"))

    channel = str(row.get("Channel") or "").lower()
    provider = str(row.get("ProviderName") or row.get("Provider") or "").lower()

    image = get_first_nonempty(row, ["NewProcessName", "Image", "ProcessName", "ExecutableInfo"])
    cmd = get_first_nonempty(row, ["CommandLine", "ProcessCommandLine", "ParentCommandLine"])
    threat = get_first_nonempty(row, ["ThreatName", "Threat", "DetectionName"])
    msg = get_first_nonempty(row, ["Message", "Description", "EventMessage", "Payload"])
    reg_path = get_first_nonempty(row, ["ObjectName", "TargetObject", "TargetFilename", "Path"])
    fs_path = get_first_nonempty(row, ["NewProcessName", "Image", "TargetFilename", "ObjectName", "Path"])

    payload_parts: List[str] = []
    for key in ("Payload", "payload", "PayloadData1", "PayloadData2", "PayloadData3",
                "PayloadData4", "PayloadData5"):
        v = row.get(key)
        if v:
            payload_parts.append(str(v).lower())
    payload_text = " ".join(payload_parts)

    image_l = image.lower()
    cmd_l = cmd.lower()
    threat_l = threat.lower()
    msg_l = msg.lower()
    reg_l = reg_path.lower()
    fs_l = fs_path.lower()

    is_security = (channel == "security")
    is_defender = ("windows defender" in channel or "windows defender" in provider or "microsoft antimalware" in provider)
    is_wmi = "microsoft-windows-wmi-activity/operational" in channel
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel

    _, ext = os.path.splitext(image_l)
    if ext in EXECUTABLE_EXTS:
        add_tag(tags, "SEC_EXECUTABLE")
    if ext in SCRIPT_EXTS:
        add_tag(tags, "SEC_SCRIPT")
    if any(x in image_l for x in ("powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe")):
        add_tag(tags, "SEC_SCRIPT")

    if ("\\temp\\" in image_l or "\\tmp\\" in image_l or "\\appdata\\" in image_l) and ext in EXECUTABLE_EXTS:
        if "hidden" in cmd_l or "+h" in cmd_l:
            add_tag(tags, "SEC_HIDDEN_EXECUTABLE")

    if any(k in image_l or k in cmd_l for k in SUSPICIOUS_NAME_KEYWORDS):
        add_tag(tags, "SEC_SUSPICIOUS_NAME")

    if any(x in image_l for x in ("\\temp\\", "\\tmp\\", "\\downloads\\")) and (ext in EXECUTABLE_EXTS or ext in SCRIPT_EXTS):
        add_tag(tags, "SEC_SUSPICIOUS_PATH")

    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|gif)\.(exe|scr|com|bat|ps1|js|vbs)$", image_l):
        add_tag(tags, "SEC_SUSPICIOUS_EXTENSION")

    if any(k in cmd_l for k in (" -enc", "-encodedcommand", "frombase64string", " base64 ")):
        add_tag(tags, "SEC_SUSPICIOUS_NAME")

    if is_security and event_id == 1102:
        add_tag(tags, "SEC_LOG_CLEARED")

    if "firewall" in channel or "firewall" in provider:
        add_tag(tags, "SEC_FIREWALL_RELATED")
    if any(x in reg_l for x in ("\\windows\\firewall", "microsoft\\windowsfirewall")):
        add_tag(tags, "SEC_FIREWALL_RELATED")

    if is_defender:
        if event_id == 1116:
            if any(x in threat_l for x in ("ransom", "locker", "crypt", "wannacry", "notpetya")):
                add_tag(tags, "SEC_RANSOMWARE_INDICATOR")
            else:
                add_tag(tags, "SEC_SUSPICIOUS_NAME")

        disabled = False

        if "set-mppreference" in cmd_l or "mpcmdrun.exe" in image_l:
            if any(x in cmd_l for x in (
                "-disablerealtimemonitoring",
                "-disablebehaviormonitoring",
                "-disableioavprotection",
                "-disableintrusionprevention",
            )):
                disabled = True

        disabled_keys = ("dpadisabled", "disablerealtimemonitoring", "disableantispyware")
        if payload_text and not disabled:
            for key in disabled_keys:
                if key in payload_text and ("= 0x1" in payload_text or "= 0x01" in payload_text or "= 1" in payload_text):
                    disabled = True
                    break

        if (not disabled and "real-time protection" in msg_l and "disabled" in msg_l):
            disabled = True

        if disabled:
            add_tag(tags, "SEC_DEFENDER_DISABLED")

        if any(x in msg_l for x in (
            "exclusionpath", "exclusionprocess", "exclusionextension",
            "added to the exclusion", "exclusion list",
        )):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")
            if "\\temp\\" in fs_l or "\\downloads\\" in fs_l or "\\users\\" in fs_l:
                add_tag(tags, "SEC_SUSPICIOUS_PATH")

    if reg_l:
        if any(pat in reg_l for pat in (
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\policies\\explorer\\run",
            "\\windows nt\\currentversion\\winlogon",
            "\\system\\currentcontrolset\\services\\",
        )):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")

    if is_security and event_id == 4657:
        if reg_l and any(pat in reg_l for pat in ("\\currentversion\\run", "\\currentversion\\runonce", "\\services\\", "\\winlogon\\")):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")

    if ("\\microsoft\\windows\\start menu\\programs\\startup" in fs_l and ext in (EXECUTABLE_EXTS | SCRIPT_EXTS)):
        add_tag(tags, "SEC_PERSISTENCE_STARTUP")

    if is_tasksched and event_id in (100, 101, 102, 106, 140, 200):
        add_tag(tags, "SEC_PERSISTENCE_TASK")
    if is_security and event_id in (4698, 4702):
        add_tag(tags, "SEC_PERSISTENCE_TASK")

    if is_wmi and event_id in (5857, 5858, 5859, 5860, 5861):
        add_tag(tags, "SEC_PERSISTENCE_WMI")

    if any(x in image_l or x in cmd_l for x in ("mimikatz", "procdump", "lsass.exe")):
        add_tag(tags, "SEC_CREDENTIAL_ACCESS")
    if is_security and event_id == 4656 and "lsass" in msg_l:
        add_tag(tags, "SEC_CREDENTIAL_ACCESS")

    if any(x in image_l for x in ("psexec", "wmic.exe", "wmiprvse.exe")):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")
    if is_security and event_id in (4648, 4768, 4769, 4770, 4771, 4772, 4778, 4779):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")
    if is_security and event_id == 5140 and any(x in msg_l for x in ("admin$", "c$")):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")
    if is_security and event_id == 4624 and ("logon type: 3" in msg_l or "logon type: 10" in msg_l):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")

    if is_security and event_id in (4672, 4673, 4674):
        add_tag(tags, "SEC_PRIVILEGE_ESCALATION")

    if is_bits and any(x in msg_l for x in ("upload", "uploaded", "sent", "bytes transferred")):
        add_tag(tags, "SEC_EXFILTRATION")

    download_keywords = ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "bitsadmin",
                         "certutil -urlcache", "certutil.exe -urlcache", "tftp ", "ftp "]
    upload_keywords = [" upload", " --upload-file", " put ", " -method post", " -x post", " --data", " --data-binary"]
    if any(k in cmd_l for k in download_keywords) and any(k in cmd_l for k in upload_keywords):
        add_tag(tags, "SEC_EXFILTRATION")

    if any(k in cmd_l for k in ("exfil", "sendto", "post ")) or "http post" in msg_l:
        add_tag(tags, "SEC_EXFILTRATION")

    if "uploaded" in msg_l or "winhttp" in msg_l:
        add_tag(tags, "SEC_EXFILTRATION")
    if any(k in cmd_l for k in ("7z.exe", "rar.exe", "winrar")):
        add_tag(tags, "SEC_EXFILTRATION")

    if "vssadmin delete shadows" in cmd_l or "shadow copies" in msg_l:
        add_tag(tags, "SEC_RANSOMWARE_INDICATOR")
    if "encrypted files" in msg_l or "file encryption" in msg_l:
        add_tag(tags, "SEC_RANSOMWARE_INDICATOR")


def tag_activity(row: Dict[str, Any], tags: Set[str]) -> None:
    event_id = safe_int(row.get("EventID"))
    if event_id is None:
        event_id = safe_int(row.get("EventId"))

    channel = str(row.get("Channel") or "").lower()
    provider = str(row.get("ProviderName") or row.get("Provider") or "").lower()

    image = get_first_nonempty(row, ["NewProcessName", "Image", "ProcessName"]).lower()
    cmd = get_first_nonempty(row, ["CommandLine", "ProcessCommandLine"]).lower()
    msg = get_first_nonempty(row, ["Message", "Description", "EventMessage", "Payload"]).lower()

    is_security = (channel == "security")
    is_system = (channel == "system")
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_powershell = "microsoft-windows-powershell/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel
    is_wininet = "wininet-config" in channel
    is_search = "microsoft-windows-search" in channel

    # 실행
    if is_security and event_id == 4688:
        add_tag(tags, "ACT_EXECUTE")
    if any(x in image for x in ("powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe")):
        add_tag(tags, "ACT_EXECUTE")
    if is_powershell and event_id in (4103, 4104, 4105, 4106):
        add_tag(tags, "ACT_EXECUTE")
    if is_system and event_id in (7000, 7001, 7035, 7036, 7040):
        add_tag(tags, "ACT_EXECUTE")
    if is_tasksched and event_id in (100, 101, 102, 107, 108, 110, 111, 118, 119, 129, 200):
        add_tag(tags, "ACT_EXECUTE")

    # 설치/제거
    if is_security and event_id == 4697:
        add_tag(tags, "ACT_INSTALL")
    if "msiexec" in image or "setup" in image or "installer" in image:
        add_tag(tags, "ACT_INSTALL")
    if "uninstall" in cmd or " remove " in cmd or cmd.startswith("uninstall"):
        add_tag(tags, "ACT_UNINSTALL")
    if is_system and event_id == 7045:
        add_tag(tags, "ACT_INSTALL")
    if is_tasksched and event_id in (106, 140):
        add_tag(tags, "ACT_INSTALL")
    if is_tasksched and event_id == 141:
        add_tag(tags, "ACT_UNINSTALL")

    # 파일 조작
    if is_security and event_id in (4660, 4663, 4670, 4656, 4658, 4662):
        add_tag(tags, "ACT_FILE_OPERATION")
    if is_security and event_id == 1102:
        add_tag(tags, "ACT_FILE_OPERATION")

    # 네트워크/로그온
    if is_security and event_id in (4624, 4625, 4634, 4647, 4648, 4768, 4769, 4770, 4771, 4772, 4778, 4779):
        add_tag(tags, "ACT_NETWORK_ACCESS")
    if is_security and event_id in (5140, 5145):
        add_tag(tags, "ACT_NETWORK_ACCESS")
        add_tag(tags, "ACT_FILE_OPERATION")
    if "termservice" in provider or "rdp" in cmd or "mstsc.exe" in image:
        add_tag(tags, "ACT_NETWORK_ACCESS")
    if "firewall" in channel or "firewall" in provider or event_id in (5154, 5155, 5156, 5157):
        add_tag(tags, "ACT_NETWORK_ACCESS")
    if is_wininet:
        add_tag(tags, "ACT_NETWORK_ACCESS")

    # 다운로드/업로드
    if is_bits and event_id in (1, 2, 3, 4, 5, 59, 60, 61, 63):
        add_tag(tags, "ACT_DOWNLOAD")
    if is_bits and any(x in msg for x in ("upload", "uploaded", "sent", "bytes transferred")):
        add_tag(tags, "ACT_UPLOAD")

    download_keywords = [
        "curl ", "wget ", "invoke-webrequest", "invoke-restmethod",
        "bitsadmin", "certutil -urlcache", "certutil.exe -urlcache",
        "tftp ", "ftp ", "http://", "https://",
    ]
    if any(k in cmd for k in download_keywords):
        add_tag(tags, "ACT_DOWNLOAD")

    upload_keywords = [" upload", " --upload-file", " put ", " -method post", " -x post", " --data", " --data-binary"]
    if any(k in cmd for k in upload_keywords):
        add_tag(tags, "ACT_UPLOAD")
    if "ftp.exe" in image and ("-s:" in cmd or " put " in cmd):
        add_tag(tags, "ACT_UPLOAD")
    if any(x in image for x in ("winscp.exe", "filezilla.exe")):
        add_tag(tags, "ACT_UPLOAD")

    # 브라우징/통신/검색
    if any(b in image for b in ("chrome.exe", "msedge.exe", "iexplore.exe", "firefox.exe", "opera.exe", "safari.exe")):
        add_tag(tags, "ACT_BROWSING")
    if any(c in image for c in ("outlook.exe", "thunderbird.exe", "teams.exe", "skype.exe", "discord.exe", "slack.exe",
                                "zoom.exe", "telegram.exe", "whatsapp", "line.exe")):
        add_tag(tags, "ACT_COMMUNICATION")

    if any(k in cmd for k in ("search-ms:", "findstr", " where ", "select-string")):
        add_tag(tags, "ACT_SEARCH")
    if is_search and event_id in (1003, 1004, 1005):
        add_tag(tags, "ACT_SEARCH")


def tag_time(row: Dict[str, Any], tags: Set[str], now_utc: datetime) -> None:
    """
    TimeCreated 기준:
      - TIME_CREATED + (TIME_RECENT/WEEK/MONTH/OLD 중 1개)
    """
    t_str = row.get("TimeCreated") or row.get("TimeCreatedUtc") or ""
    dt = parse_time(t_str)
    if not dt:
        return

    add_tag(tags, "TIME_CREATED")

    delta = now_utc - dt
    if delta <= DELTA_RECENT:
        add_tag(tags, "TIME_RECENT")
    elif delta <= DELTA_WEEK:
        add_tag(tags, "TIME_WEEK")
    elif delta <= DELTA_MONTH:
        add_tag(tags, "TIME_MONTH")
    else:
        add_tag(tags, "TIME_OLD")


def tag_state(_: Dict[str, Any], tags: Set[str]) -> None:
    add_tag(tags, "STATE_ACTIVE")


def build_tags(row: Dict[str, Any], now_utc: datetime) -> List[str]:
    tags: Set[str] = set()
    tag_artifact(row, tags)
    tag_event(row, tags)
    tag_area(row, tags)
    tag_security(row, tags)
    tag_format(row, tags)
    tag_activity(row, tags)
    tag_time(row, tags, now_utc)
    tag_state(row, tags)
    return sorted(tags)


def build_type_label(row: Dict[str, Any]) -> str:
    event_id = safe_int(row.get("EventID"))
    if event_id is None:
        event_id = safe_int(row.get("EventId"))
    return f"eventlog_{event_id}" if event_id is not None else "eventlog_unknown"


def build_time_label(row: Dict[str, Any]) -> str:
    t_str = row.get("TimeCreated") or row.get("TimeCreatedUtc") or ""
    dt = parse_time(t_str)
    if not dt:
        return str(t_str).strip()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def build_description(row: Dict[str, Any]) -> str:
    parts: List[str] = []

    def add(label: str, candidates: List[str]) -> None:
        v = get_first_nonempty(row, candidates)
        if v:
            parts.append(f"{label} : {v}")

    add("TimeCreated", ["TimeCreated", "TimeCreatedUtc"])
    add("Channel", ["Channel"])
    add("Provider", ["ProviderName", "Provider"])
    add("EventID", ["EventID", "EventId"])
    add("Computer", ["Computer"])
    add("SubjectUser", ["SubjectUserName"])
    add("TargetUser", ["TargetUserName"])
    add("LogonType", ["LogonType"])
    add("NewProcessName", ["NewProcessName", "Image", "ProcessName"])
    add("CommandLine", ["CommandLine", "ProcessCommandLine"])
    add("ParentProcessName", ["ParentProcessName"])
    add("ParentCommandLine", ["ParentCommandLine"])
    add("IpAddress", ["IpAddress"])
    add("IpPort", ["IpPort"])
    add("TaskCategory", ["TaskCategory"])
    add("Message", ["Message", "Description", "EventMessage", "Payload"])

    return " | ".join(parts)


# ============================================================
# 4) EvtxECmd CSV 스키마 판별(2차 필터)
# ============================================================

def is_evtxecmd_schema(fieldnames: List[str]) -> bool:
    lower = {f.lower() for f in fieldnames}
    # 최소 후보: 시간 + 이벤트ID + 채널
    if not (("timecreated" in lower) or ("timecreatedutc" in lower)):
        return False
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        # 위 라인은 실수/중복 방지를 위해 아래로 교체 (실제 체크)
        pass
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass
    if not (("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    # 실제 유효 체크
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    # 최종 체크(정상)
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    # EvtxECmd는 보통 "EventID" 또는 "EventId"
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower)):
        pass

    if not (("eventid" in lower) or ("eventid" in lower)):
        pass

    # 실제 조건
    if not (("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower) or ("eventid" in lower)):
        pass

    # 여기서부터는 “실제 필요한 최소 조건”만 유지
    if not (("eventid" in lower) or ("eventid" in lower)):
        return False
    if "channel" not in lower:
        return False
    return True


# ============================================================
# 5) CSV 읽기/쓰기
# ============================================================

def _read_csv_rows(csv_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    encodings = ["utf-8-sig", "utf-8", "cp949"]
    last_err: Optional[Exception] = None

    for enc in encodings:
        try:
            with csv_path.open("r", encoding=enc, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
            last_err = None
            break
        except Exception as e:
            last_err = e
            rows = []

    if last_err is not None:
        print(f"[SKIP] CSV 읽기 실패(인코딩 모두 실패): {csv_path} -> {last_err}")
        return []
    return rows


def process_evtx_csv(csv_path: Path, out_csv: Path, now_utc: datetime) -> int:
    rows = _read_csv_rows(csv_path)
    if not rows:
        raise ValueError("빈 CSV 또는 읽기 실패")

    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=OUT_FIELDNAMES)
        writer.writeheader()

        out_count = 0
        for row in rows:
            tags = build_tags(row, now_utc)
            writer.writerow(
                {
                    "type": build_type_label(row),
                    "time": build_time_label(row),
                    "description": build_description(row),
                    "tags": "|".join(tags),
                }
            )
            out_count += 1

    return out_count


# ============================================================
# 6) 자동 탐색 + 출력 경로 구성
# ============================================================

def _find_kape_output_root(drive_root: Path) -> Optional[Path]:
    cand1 = drive_root / "Kape Output"
    if cand1.exists():
        return cand1
    cand2 = drive_root / "KAPE Output"
    if cand2.exists():
        return cand2
    return None


def _get_case_root(csv_path: Path) -> Optional[Path]:
    """
    <드라이브>:\\Kape Output\\<CASE>\\...\\file.csv 에서
    <드라이브>:\\Kape Output\\<CASE> 경로 반환
    """
    p = csv_path
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None
            if not rel.parts:
                return None
            return parent / rel.parts[0]
    return None


def _get_case_name(csv_path: Path) -> Optional[str]:
    case_root = _get_case_root(csv_path)
    return case_root.name if case_root else None


def _ensure_unique_output_path(path: Path) -> Path:
    if not path.exists():
        return path
    base = path.with_suffix("")
    ext = path.suffix
    idx = 1
    while True:
        candidate = Path(f"{base}_v{idx}{ext}")
        if not candidate.exists():
            return candidate
        idx += 1


def _get_output_path(csv_path: Path, case_name: Optional[str]) -> Path:
    """
    출력: <드라이브>:\\tagged\\eventlog_<Drive>_<stem>_<CASE>_tagged.csv
          CASE 없으면 eventlog_<Drive>_<stem>_tagged.csv
    """
    drive = csv_path.drive or "D:"
    drive_letter = drive.rstrip(":").upper() if drive else "D"

    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stem = csv_path.stem
    if case_name:
        out_name = f"eventlog_{drive_letter}_{stem}_{case_name}_tagged.csv"
    else:
        out_name = f"eventlog_{drive_letter}_{stem}_tagged.csv"

    return _ensure_unique_output_path(tagged_dir / out_name)


def _find_candidate_csvs() -> List[Path]:
    """
    1) D:~Z: 각 드라이브의 Kape Output 아래에서
       - 먼저 TARGET_GLOB 로 후보 수집
    2) 1)에서 아무것도 못 찾으면,
       - Kape Output 아래의 모든 *.csv 를 헤더 스키마로 필터링(느리지만 인자 없이 실행 지원)
    """
    glob_hits: List[Path] = []
    all_csvs: List[Path] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = _find_kape_output_root(drive_root)
        if not kape_root:
            continue

        # 1) glob 기반
        for p in kape_root.rglob(TARGET_GLOB):
            if p.is_file():
                glob_hits.append(p)

        # 2) fallback용 전체 csv
        for p in kape_root.rglob("*.csv"):
            if p.is_file():
                all_csvs.append(p)

    if glob_hits:
        return glob_hits

    # 헤더 스키마 기반
    schema_hits: List[Path] = []
    for p in all_csvs:
        try:
            with p.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue
                if is_evtxecmd_schema(header):
                    schema_hits.append(p)
        except Exception:
            continue

    return schema_hits


# ============================================================
# 7) 메인 실행
# ============================================================

def main() -> None:
    print("[AUTO] 인자 없이 실행: D:~Z: 에서 Kape Output 아래 EvtxECmd CSV 자동 탐색")
    print(f"[AUTO] 1차 필터: {TARGET_GLOB}")

    candidates = _find_candidate_csvs()
    if not candidates:
        print("[END] 대상 CSV 없음")
        return

    print(f"[AUTO] 대상 CSV {len(candidates)}개 발견")

    # case_root별 analysis_time 캐시
    analysis_time_cache: Dict[str, datetime] = {}

    for csv_path in candidates:
        case_root = _get_case_root(csv_path)
        case_name = _get_case_name(csv_path)

        # 기준시간(now)은 “케이스 내 로그 파일명 timestamp” 우선
        cache_key = str(case_root) if case_root else "__NOCASE__" + (csv_path.drive or "")
        if cache_key in analysis_time_cache:
            now_utc = analysis_time_cache[cache_key]
        else:
            now_utc = _get_analysis_time_for_case(case_root) if case_root else datetime.now(timezone.utc)
            analysis_time_cache[cache_key] = now_utc

        out_path = _get_output_path(csv_path, case_name)

        print(f"\n[+] Input : {csv_path}")
        print(f"[+] Output: {out_path}")
        print(f"[+] BaseTime(now_utc): {now_utc.isoformat()}")

        try:
            rows = process_evtx_csv(csv_path, out_path, now_utc)
            print(f"[OK] rows={rows}")
        except Exception as e:
            print(f"[SKIP] 처리 실패: {e}")


if __name__ == "__main__":
    main()
