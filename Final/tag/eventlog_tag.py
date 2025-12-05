# 파일: tag/eventlog_tag.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Iterable, Any


# ───────────────────── 공통 유틸 ─────────────────────

def safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def get_first_nonempty(row: Dict[str, Any], candidates: List[str]) -> str:
    for key in candidates:
        v = row.get(key)
        if v is not None:
            v_str = str(v).strip()
            if v_str:
                return v_str
    return ""


def parse_time(timestr: str) -> Optional[datetime]:
    if not timestr:
        return None
    s = timestr.strip()
    s = re.sub(r"\s*(UTC|Z)$", "", s, flags=re.IGNORECASE)
    patterns = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in patterns:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def add_tag(tags: Set[str], value: Optional[str]) -> None:
    if value:
        tags.add(value)


def _get_analysis_time(cfg: dict) -> datetime:
    """cfg['ANALYSIS_TIME'] 있으면 우선, 없으면 지금 시간(UTC)."""
    v = cfg.get("ANALYSIS_TIME")
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


# ───────────────────── 태깅 로직 ─────────────────────
# 1) ARTIFACT_

def tag_artifact(row: Dict[str, Any], tags: Set[str]) -> None:
    add_tag(tags, "ARTIFACT_EVENT_LOG")


# 2) EVENT_ ─ 이벤트 ID / 채널 기반

def tag_event(row: Dict[str, Any], tags: Set[str]) -> None:
    event_id = safe_int(row.get("EventID"))
    channel_raw = row.get("Channel") or ""
    channel = str(channel_raw).lower()
    provider_raw = row.get("ProviderName") or row.get("Provider") or ""
    provider = str(provider_raw).lower()

    is_security = (channel == "security")
    is_system = (channel == "system")
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_defender = "microsoft-windows-windows defender" in channel
    is_powershell = "microsoft-windows-powershell/operational" in channel
    is_sysmon = ("sysmon" in channel) or ("sysmon" in provider)
    is_wmi = "microsoft-windows-wmi-activity/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel

    # 1) Security
    if is_security and event_id is not None:
        # 프로세스 생성 / 종료
        if event_id == 4688:
            add_tag(tags, "EVENT_CREATE")
            add_tag(tags, "EVENT_EXECUTED")
        elif event_id == 4689:
            add_tag(tags, "EVENT_DELETE")

        # 계정 생성 / 상태변경 / 삭제
        if event_id in (4720,):
            add_tag(tags, "EVENT_CREATE")
        if event_id in (4722, 4723, 4724, 4725, 4727, 4738, 4767, 4740):
            add_tag(tags, "EVENT_MODIFY")
        if event_id in (4726,):
            add_tag(tags, "EVENT_DELETE")

        # 그룹 멤버십 변경
        if event_id in (
            4728, 4729, 4732, 4733, 4735, 4737,
            4756, 4757, 4758, 4761, 4762,
        ):
            add_tag(tags, "EVENT_MODIFY")

        # 로그온/로그오프/인증, Kerberos, RDP
        if event_id in (
            4624, 4625, 4634, 4647, 4648,
            4768, 4769, 4770, 4771, 4772,
            4776, 4778, 4779,
        ):
            add_tag(tags, "EVENT_ACCESSED")

        # 특권 사용 / 민감 권한
        if event_id in (4672, 4673, 4674):
            add_tag(tags, "EVENT_ACCESSED")

        # 감사/보안 정책 변경
        if event_id in (4719, 4739, 4902, 4904, 4905, 4907):
            add_tag(tags, "EVENT_MODIFY")

        # 레지스트리/객체 접근
        if event_id in (4660, 4663, 4670, 4656, 4658, 4662, 4657):
            add_tag(tags, "EVENT_ACCESSED")

        # 서비스 / 예약 작업 (보안 로그 관점)
        if event_id == 4697:
            add_tag(tags, "EVENT_CREATE")
        if event_id == 4698:
            add_tag(tags, "EVENT_CREATE")
        if event_id == 4699:
            add_tag(tags, "EVENT_DELETE")
        if event_id == 4702:
            add_tag(tags, "EVENT_MODIFY")

        # 로그 clear
        if event_id == 1102:
            add_tag(tags, "EVENT_DELETE")

        # Filtering Platform (네트워크 연결 허용 등)
        if event_id in (5154, 5155, 5156, 5157):
            add_tag(tags, "EVENT_ACCESSED")

    # 2) Sysmon
    if is_sysmon and event_id is not None:
        if event_id == 1:   # Process Create
            add_tag(tags, "EVENT_CREATE")
            add_tag(tags, "EVENT_EXECUTED")
        elif event_id == 5: # Process Terminate
            add_tag(tags, "EVENT_DELETE")
        elif event_id in (2, 11, 23):  # 파일 생성/삭제/드라이버 등
            add_tag(tags, "EVENT_CREATE")
        elif event_id in (12, 13, 14): # Registry add/modify/delete
            add_tag(tags, "EVENT_MODIFY")

    # 3) System
    if is_system and event_id is not None:
        if event_id in (7000, 7001, 7035, 7036):
            add_tag(tags, "EVENT_EXECUTED")
        if event_id == 7040:
            add_tag(tags, "EVENT_MODIFY")
        if event_id == 7045:   # 서비스 설치
            add_tag(tags, "EVENT_CREATE")
        if event_id in (6005, 6006, 6008, 6009):
            add_tag(tags, "EVENT_MODIFY")

    # 4) Task Scheduler
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

    # 5) Defender
    if is_defender and event_id is not None:
        if event_id == 1116:   # Malware detected
            add_tag(tags, "EVENT_ACCESSED")
        if event_id in (5000, 5001, 5004, 5007, 5010):
            add_tag(tags, "EVENT_MODIFY")

    # 6) PowerShell
    if is_powershell and event_id is not None:
        if event_id in (4103, 4104, 4105, 4106):
            add_tag(tags, "EVENT_EXECUTED")

    # 7) WMI Activity
    if is_wmi and event_id is not None:
        if event_id in (5857, 5858, 5859, 5860, 5861):
            add_tag(tags, "EVENT_EXECUTED")

    # 8) BITS Client
    if is_bits and event_id is not None:
        if event_id in (1, 2, 3, 4, 5, 59, 60, 61, 63):
            add_tag(tags, "EVENT_ACCESSED")

    # fallback
    if not any(t.startswith("EVENT_") for t in tags):
        add_tag(tags, "EVENT_ACCESSED")


# 3) AREA_ ─ 경로 기반

def tag_area(row: Dict[str, Any], tags: Set[str]) -> None:
    path = get_first_nonempty(
        row,
        [
            "NewProcessName",
            "Image",
            "Path",
            "TargetFilename",
            "ObjectName",
        ],
    )
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


# 4) SEC_ ─ 보안 관점 태그

def tag_security(row: Dict[str, Any], tags: Set[str]) -> None:
    event_id = safe_int(row.get("EventID"))
    channel = str(row.get("Channel") or "").lower()
    provider = str(row.get("ProviderName") or row.get("Provider") or "").lower()

    image = get_first_nonempty(
        row,
        ["NewProcessName", "Image", "ProcessName", "ExecutableInfo"],
    )
    cmd = get_first_nonempty(
        row,
        ["CommandLine", "ProcessCommandLine", "ParentCommandLine"],
    )
    threat = get_first_nonempty(
        row,
        ["ThreatName", "Threat", "DetectionName"],
    )
    msg = get_first_nonempty(
        row,
        ["Message", "Description", "EventMessage", "Payload"],
    )
    reg_path = get_first_nonempty(
        row,
        ["ObjectName", "TargetObject", "TargetFilename", "Path"],
    )
    fs_path = get_first_nonempty(
        row,
        ["NewProcessName", "Image", "TargetFilename", "ObjectName", "Path"],
    )

    payload_parts: List[str] = []
    for key in (
        "Payload", "payload",
        "PayloadData1", "PayloadData2", "PayloadData3",
        "PayloadData4", "PayloadData5",
    ):
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
    is_defender = (
        "windows defender" in channel
        or "windows defender" in provider
        or "microsoft antimalware" in provider
    )
    is_wmi = "microsoft-windows-wmi-activity/operational" in channel
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel

    # 실행 파일 / 스크립트
    _, ext = os.path.splitext(image_l)
    if ext in (".exe", ".dll", ".sys", ".scr", ".com"):
        add_tag(tags, "SEC_EXECUTABLE")
    if ext in (".ps1", ".bat", ".cmd", ".vbs", ".js"):
        add_tag(tags, "SEC_SCRIPT")

    if any(x in image_l for x in ("powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe")):
        add_tag(tags, "SEC_SCRIPT")

    # 숨김 실행
    if ("\\temp\\" in image_l or "\\appdata\\" in image_l) and ext in (
        ".exe", ".dll", ".scr", ".com"
    ):
        if "hidden" in cmd_l or "+h" in cmd_l:
            add_tag(tags, "SEC_HIDDEN_EXECUTABLE")

    # 의심스러운 이름/경로/확장자
    suspicious_keywords = [
        "crack", "keygen", "mimikatz", "purelogs", "vidar",
        "miner", "xmrig", "wannacry", "notpetya", "backdoor",
    ]
    if any(k in image_l or k in cmd_l for k in suspicious_keywords):
        add_tag(tags, "SEC_SUSPICIOUS_NAME")

    if any(x in image_l for x in ("\\temp\\", "\\downloads\\")) and ext in (
        ".exe", ".dll", ".scr", ".com", ".ps1", ".vbs", ".js",
    ):
        add_tag(tags, "SEC_SUSPICIOUS_PATH")

    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|gif)\.(exe|scr|com)$", image_l):
        add_tag(tags, "SEC_SUSPICIOUS_EXTENSION")

    # 로그 삭제
    if is_security and event_id == 1102:
        add_tag(tags, "SEC_LOG_CLEARED")

    # Firewall / Filtering Platform
    if "firewall" in channel or "firewall" in provider:
        add_tag(tags, "SEC_FIREWALL_RELATED")

    # Defender: 탐지 + 비활성화 + 예외 추가
    if is_defender:
        # 탐지 → 랜섬웨어 여부
        if event_id == 1116:
            if any(x in threat_l for x in ("ransom", "locker", "crypt", "wannacry", "notpetya")):
                add_tag(tags, "SEC_RANSOMWARE_INDICATOR")
            else:
                add_tag(tags, "SEC_SUSPICIOUS_NAME")

        disabled = False

        # (1) Set-MpPreference 기반 비활성화
        if "set-mppreference" in cmd_l or "mpcmdrun.exe" in image_l:
            if any(x in cmd_l for x in (
                "-disablerealtimemonitoring",
                "-disablebehaviormonitoring",
                "-disableioavprotection",
                "-disableintrusionprevention",
            )):
                disabled = True

        # (2) Payload 상의 레지스트리 값
        disabled_keys = ("dpadisabled", "disablerealtimemonitoring", "disableantispyware")
        if payload_text and not disabled:
            for key in disabled_keys:
                if key in payload_text and (
                    "= 0x1" in payload_text or
                    "= 0x01" in payload_text or
                    "= 1" in payload_text
                ):
                    disabled = True
                    break

        # (3) 메시지 문구
        if (not disabled and
                "real-time protection" in msg_l and
                "disabled" in msg_l):
            disabled = True

        if disabled:
            add_tag(tags, "SEC_DEFENDER_DISABLED")

        # Defender 예외 추가(Exclusion)
        if any(x in msg_l for x in (
            "exclusionpath", "exclusionprocess", "exclusionextension",
            "added to the exclusion", "exclusion list",
        )):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")
            if "\\temp\\" in fs_l or "\\downloads\\" in fs_l or "\\users\\" in fs_l:
                add_tag(tags, "SEC_SUSPICIOUS_PATH")

    # 지속성: 레지스트리 Run / Services / Winlogon
    if reg_l:
        if any(pat in reg_l for pat in (
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\policies\\explorer\\run",
            "\\windows nt\\currentversion\\winlogon",
            "\\system\\currentcontrolset\\services\\",
        )):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")

    if (("sysmon" in channel or "sysmon" in provider) and event_id in (12, 13, 14)) or (
        is_security and event_id == 4657
    ):
        if reg_l and any(pat in reg_l for pat in (
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\services\\",
            "\\winlogon\\",
        )):
            add_tag(tags, "SEC_PERSISTENCE_REGISTRY")

    # 지속성: Startup 폴더
    if (
        "\\microsoft\\windows\\start menu\\programs\\startup" in fs_l
        and ext in (".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs")
    ):
        add_tag(tags, "SEC_PERSISTENCE_STARTUP")

    # 지속성: 예약 작업
    if is_tasksched and event_id in (100, 101, 102, 106, 140, 200):
        add_tag(tags, "SEC_PERSISTENCE_TASK")
    if is_security and event_id in (4698, 4702):
        add_tag(tags, "SEC_PERSISTENCE_TASK")

    # 지속성: WMI Activity
    if is_wmi and event_id in (5857, 5858, 5859, 5860, 5861):
        add_tag(tags, "SEC_PERSISTENCE_WMI")

    # 자격증명 접근
    if any(x in image_l or x in cmd_l for x in ("mimikatz", "procdump", "lsass.exe")):
        add_tag(tags, "SEC_CREDENTIAL_ACCESS")

    # 측면 이동
    if any(x in image_l for x in ("psexec", "wmic.exe", "wmiprvse.exe")):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")
    if is_security and event_id in (4648, 4768, 4769, 4770, 4771, 4772, 4778, 4779):
        add_tag(tags, "SEC_LATERAL_MOVEMENT")

    # 권한 상승
    if is_security and event_id in (4672, 4673, 4674):
        add_tag(tags, "SEC_PRIVILEGE_ESCALATION")

    # 유출/Exfiltration 시그널 (BITS + HTTP POST 등)
    if is_bits:
        if any(x in msg_l for x in ("upload", "uploaded", "sent", "bytes transferred")):
            add_tag(tags, "SEC_EXFILTRATION")

    download_keywords = [
        "curl ", "wget ", "invoke-webrequest", "invoke-restmethod",
        "bitsadmin", "certutil -urlcache", "certutil.exe -urlcache",
        "tftp ", "ftp ",
    ]
    upload_keywords = [
        " upload", " --upload-file", " put ", " -method post",
        " -x post", " --data", " --data-binary",
    ]
    if any(k in cmd_l for k in download_keywords) and any(k in cmd_l for k in upload_keywords):
        add_tag(tags, "SEC_EXFILTRATION")

    if any(k in cmd_l for k in ("exfil", "sendto", "post ")) or "http post" in msg_l:
        add_tag(tags, "SEC_EXFILTRATION")


# 5) FORMAT_ ─ 파일 포맷

def tag_format(row: Dict[str, Any], tags: Set[str]) -> None:
    path = get_first_nonempty(
        row,
        [
            "NewProcessName",
            "Image",
            "TargetFilename",
            "ObjectName",
        ],
    )
    if not path:
        return
    _, ext = os.path.splitext(path.lower())

    if ext in (".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt"):
        add_tag(tags, "FORMAT_DOCUMENT")
    elif ext in (".xls", ".xlsx", ".csv"):
        add_tag(tags, "FORMAT_SPREADSHEET")
    elif ext in (".ppt", ".pptx"):
        add_tag(tags, "FORMAT_PRESENTATION")
    elif ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg"):
        add_tag(tags, "FORMAT_IMAGE")
    elif ext in (".mp4", ".avi", ".mkv", ".mov", ".wmv"):
        add_tag(tags, "FORMAT_VIDEO")
    elif ext in (".mp3", ".wav", ".flac", ".wma"):
        add_tag(tags, "FORMAT_AUDIO")
    elif ext in (".zip", ".rar", ".7z", ".tar", ".gz"):
        add_tag(tags, "FORMAT_ARCHIVE")
    elif ext in (".exe", ".dll", ".sys", ".com", ".scr"):
        add_tag(tags, "FORMAT_EXECUTABLE")
    elif ext in (".ps1", ".bat", ".vbs", ".js", ".py", ".cmd"):
        add_tag(tags, "FORMAT_SCRIPT")
    elif ext in (".db", ".sqlite", ".accdb", ".mdb"):
        add_tag(tags, "FORMAT_DATABASE")
    elif ext in (".evtx", ".log"):
        add_tag(tags, "FORMAT_LOG")
    elif ext in (".ini", ".xml", ".json", ".yaml", ".yml", ".conf", ".cfg"):
        add_tag(tags, "FORMAT_CONFIG")
    elif ext in (".dat", ".hve", ".reg"):
        add_tag(tags, "FORMAT_REGISTRY")
    elif ext in (".pst", ".ost", ".msg", ".eml"):
        add_tag(tags, "FORMAT_EMAIL")
    elif ext in (".lnk", ".url"):
        add_tag(tags, "FORMAT_SHORTCUT")


# 6) ACT_ ─ 활동 관점

def tag_activity(row: Dict[str, Any], tags: Set[str]) -> None:
    event_id = safe_int(row.get("EventID"))
    channel = str(row.get("Channel") or "").lower()
    provider = str(row.get("ProviderName") or row.get("Provider") or "").lower()
    image = get_first_nonempty(
        row,
        ["NewProcessName", "Image", "ProcessName"],
    ).lower()
    cmd = get_first_nonempty(
        row,
        ["CommandLine", "ProcessCommandLine"],
    ).lower()
    msg = get_first_nonempty(
        row,
        ["Message", "Description", "EventMessage", "Payload"],
    ).lower()

    is_security = (channel == "security")
    is_system = (channel == "system")
    is_tasksched = "microsoft-windows-taskscheduler/operational" in channel
    is_powershell = "microsoft-windows-powershell/operational" in channel
    is_bits = "microsoft-windows-bits-client/operational" in channel
    is_wininet = "wininet-config" in channel

    # 실행
    if (is_security and event_id == 4688) or (
        ("sysmon" in channel or "sysmon" in provider) and event_id == 1
    ):
        add_tag(tags, "ACT_EXECUTE")

    if any(x in image for x in ("powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe")):
        add_tag(tags, "ACT_EXECUTE")

    if is_powershell and event_id in (4103, 4104, 4105, 4106):
        add_tag(tags, "ACT_EXECUTE")

    # 설치 / 제거
    if is_security and event_id == 4697:
        add_tag(tags, "ACT_INSTALL")
    if "msiexec" in image or "setup" in image or "installer" in image:
        add_tag(tags, "ACT_INSTALL")
    if "uninstall" in cmd or "remove" in cmd:
        add_tag(tags, "ACT_UNINSTALL")

    if is_system and event_id in (7045,):
        add_tag(tags, "ACT_INSTALL")
    if is_system and event_id in (7000, 7001, 7035, 7036, 7040):
        add_tag(tags, "ACT_EXECUTE")

    if is_tasksched and event_id is not None:
        if event_id in (100, 101, 102, 107, 108, 110, 111, 118, 119, 129, 200):
            add_tag(tags, "ACT_EXECUTE")
        if event_id in (106, 140):
            add_tag(tags, "ACT_INSTALL")
        if event_id == 141:
            add_tag(tags, "ACT_UNINSTALL")

    # 파일 조작
    if is_security and event_id in (4660, 4663, 4670, 4656, 4658, 4662):
        add_tag(tags, "ACT_FILE_OPERATION")

    # 네트워크 접근 / 로그인 / RDP
    if is_security and event_id in (
        4624, 4625, 4634, 4647, 4648,
        4768, 4769, 4770, 4771, 4772, 4778, 4779,
    ):
        add_tag(tags, "ACT_NETWORK_ACCESS")
    if "termservice" in provider or "rdp" in cmd or "mstsc.exe" in image:
        add_tag(tags, "ACT_NETWORK_ACCESS")
    if "firewall" in channel or "firewall" in provider or event_id in (5154, 5155, 5156, 5157):
        add_tag(tags, "ACT_NETWORK_ACCESS")

    if is_wininet:
        add_tag(tags, "ACT_NETWORK_ACCESS")

    # 다운로드 / 업로드 / BITS / CLI 도구
    if is_bits:
        if event_id in (1, 2, 3, 4, 5, 59, 60, 61, 63):
            add_tag(tags, "ACT_DOWNLOAD")
        if any(x in msg for x in ("upload", "uploaded", "sent", "bytes transferred")):
            add_tag(tags, "ACT_UPLOAD")

    download_keywords = [
        "curl ", "wget ", "invoke-webrequest", "invoke-restmethod",
        "bitsadmin", "certutil -urlcache", "certutil.exe -urlcache",
        "tftp ", "ftp ",
    ]
    if any(k in cmd for k in download_keywords):
        add_tag(tags, "ACT_DOWNLOAD")

    upload_keywords = [
        " upload", " --upload-file", " put ", " -method post",
        " -x post", " --data", " --data-binary",
    ]
    if any(k in cmd for k in upload_keywords):
        add_tag(tags, "ACT_UPLOAD")

    # 브라우징 / 통신 / 검색
    browser_procs = [
        "chrome.exe", "msedge.exe", "iexplore.exe",
        "firefox.exe", "opera.exe",
    ]
    if any(b in image for b in browser_procs):
        add_tag(tags, "ACT_BROWSING")

    comm_procs = [
        "outlook.exe", "thunderbird.exe", "teams.exe",
        "skype.exe", "discord.exe", "slack.exe",
        "zoom.exe", "telegram.exe", "whatsapp", "line.exe",
    ]
    if any(c in image for c in comm_procs):
        add_tag(tags, "ACT_COMMUNICATION")

    if any(k in cmd for k in ("search-ms:", "findstr", "where ", "select-string")):
        add_tag(tags, "ACT_SEARCH")

    if "microsoft-windows-search" in channel and event_id in (1003, 1004, 1005):
        add_tag(tags, "ACT_SEARCH")


# 7) TIME_ ─ TimeCreated 기준

def tag_time(row: Dict[str, Any], tags: Set[str], now: datetime) -> None:
    t_str = row.get("TimeCreated") or row.get("TimeCreatedUtc") or ""
    dt = parse_time(t_str)
    if not dt:
        return

    add_tag(tags, "TIME_CREATED")

    delta = now - dt
    if delta < timedelta(days=1):
        add_tag(tags, "TIME_RECENT")
    if delta < timedelta(days=7):
        add_tag(tags, "TIME_WEEK")
    if delta < timedelta(days=31):
        add_tag(tags, "TIME_MONTH")
    if delta > timedelta(days=90):
        add_tag(tags, "TIME_OLD")


# 8) STATE_ ─ 상태

def tag_state(row: Dict[str, Any], tags: Set[str]) -> None:
    add_tag(tags, "STATE_ACTIVE")


def build_tags(row: Dict[str, Any], now: datetime) -> List[str]:
    tags: Set[str] = set()

    tag_artifact(row, tags)
    tag_event(row, tags)
    tag_area(row, tags)
    tag_security(row, tags)
    tag_format(row, tags)
    tag_activity(row, tags)
    tag_time(row, tags, now)
    tag_state(row, tags)

    return sorted(tags)


# // [코드 삽입 시작] type / time / description 빌더

def build_type_label(row: Dict[str, Any]) -> str:
    """
    type 컬럼: eventlog_<EventID> 형태 (예: eventlog_4688)
    EventID 없으면 eventlog_unknown.
    """
    event_id = safe_int(row.get("EventID"))
    if event_id is not None:
        return f"eventlog_{event_id}"
    return "eventlog_unknown"


def build_time_label(row: Dict[str, Any]) -> str:
    """
    time 컬럼: TimeCreated/TimeCreatedUtc 기준 마지막 사용 시간.
    포맷: YYYY-MM-DD HH:MM:SS
    """
    t_str = row.get("TimeCreated") or row.get("TimeCreatedUtc") or ""
    dt = parse_time(t_str)
    if not dt:
        return t_str.strip()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build_description(row: Dict[str, Any]) -> str:
    """
    description 컬럼: 주요 필드를
    'Key : Value | Key2 : Value2' 형식으로 합쳐서 LLM이 보기 좋게 요약.
    """
    parts: List[str] = []

    def add(label: str, candidates: List[str]) -> None:
        v = get_first_nonempty(row, candidates)
        if v:
            parts.append(f"{label} : {v}")

    add("TimeCreated", ["TimeCreated", "TimeCreatedUtc"])
    add("Channel", ["Channel"])
    add("Provider", ["ProviderName", "Provider"])
    add("EventID", ["EventID"])
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

# // [코드 삽입 끝]


# ───────────────────── CSV 처리 ─────────────────────

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
        print(f"[!] Failed to read CSV (all encodings): {csv_path} -> {last_err}")
        return []

    return rows


def process_evtx_csv(
    csv_path: Path,
    tag_root: Path,
    drive_tag: str,
    analysis_time: datetime,
) -> Optional[Path]:
    print(f"[+] Processing EvtxECmd CSV: {csv_path}")

    rows = _read_csv_rows(csv_path)
    if not rows:
        print(f"[!] Empty or unreadable CSV: {csv_path}")
        return None

    tag_root.mkdir(parents=True, exist_ok=True)

    # 출력 파일 이름: eventlog_<드라이브>_<원본이름>_tagged.csv
    base_name = csv_path.stem  # ex) Security_EvtxECmd_Output
    out_name = f"eventlog_{drive_tag}_{base_name}_tagged.csv"
    out_csv = tag_root / out_name

    # // [코드 삽입 시작] 최종 출력: type / time / description / tags 4컬럼
    fieldnames = ["type", "time", "description", "tags"]

    with out_csv.open("w", encoding="utf-8", newline="") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            tags = build_tags(row, analysis_time)
            row_out = {
                "type": build_type_label(row),
                "time": build_time_label(row),
                "description": build_description(row),
                "tags": "|".join(tags),
            }
            writer.writerow(row_out)
    # // [코드 삽입 끝]

    print(f"    -> {out_csv}")
    return out_csv


# ───────────────────── 엔트리포인트 ─────────────────────

def run(drive_letters: List[str], cfg: dict) -> bool:
    """
    main.py 에서 호출:
        import tag.eventlog_tag as m
        m.run(drive_letters, cfg)

    - drive_letters: ["H:", "I:", ...]
    - cfg: {
        "BASE_OUT": Path(...),
        "KAPE_EXE": Path(...),
        "PROC_TIMEOUT_SEC": int,
        (optional) "ANALYSIS_TIME": datetime or ISO string
      }
    """
    base_out: Path = cfg["BASE_OUT"]
    analysis_time = _get_analysis_time(cfg)

    # tagged 루트: BASE_OUT.parent / "tagged"
    tag_root = base_out.parent / "tagged"

    any_done = False

    for dl in drive_letters:
        drive_tag = dl.rstrip(":").upper()
        evtx_root = base_out / drive_tag / "EvtxECmd"

        if not evtx_root.exists():
            print(f"[SKIP] eventlog_tag: {drive_tag} EvtxECmd 폴더 없음 → {evtx_root}")
            continue

        csv_files = list(evtx_root.rglob("*EvtxECmd*_Output.csv"))
        if not csv_files:
            print(f"[SKIP] eventlog_tag: {drive_tag} EvtxECmd CSV 없음 → {evtx_root}")
            continue

        print(f"[INFO] eventlog_tag: {drive_tag} 대상 CSV {len(csv_files)}개")
        for csv_path in csv_files:
            out = process_evtx_csv(csv_path, tag_root, drive_tag, analysis_time)
            if out is not None:
                any_done = True

    if not any_done:
        print("[INFO] eventlog_tag: 처리된 CSV가 없습니다.")
    else:
        print("[INFO] eventlog_tag: 완료")

    return any_done
