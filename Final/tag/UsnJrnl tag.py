#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
from datetime import datetime, timedelta, timezone

# ──────────────────────────────────────────────────────────────
#  태그 정의: 확장자/경로/속성 기반 매핑
# ──────────────────────────────────────────────────────────────

EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".com", ".scr"}
SCRIPT_EXTS = {".ps1", ".bat", ".vbs", ".js", ".py", ".cmd"}
DOCUMENT_EXTS = {".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt"}
SPREADSHEET_EXTS = {".xls", ".xlsx", ".csv"}
PRESENTATION_EXTS = {".ppt", ".pptx"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg"}
VIDEO_EXTS = {".mp4", ".avi", ".mkv", ".mov", ".wmv"}
AUDIO_EXTS = {".mp3", ".wav", ".flac", ".wma"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz"}
DATABASE_EXTS = {".db", ".sqlite", ".accdb", ".mdb"}
LOG_EXTS = {".evtx", ".log"}
CONFIG_EXTS = {".ini", ".xml", ".json", ".yaml", ".yml", ".conf", ".cfg"}
REGISTRY_EXTS = {".dat", ".hve", ".reg"}
EMAIL_EXTS = {".pst", ".ost", ".msg", ".eml"}
SHORTCUT_EXTS = {".lnk", ".url"}

SUSPICIOUS_NAME_KEYWORDS = {
    "crack",
    "keygen",
    "payload",
    "backdoor",
    "mimikatz",
}

# USN CSV에서 사용할 수 있는 대표 컬럼 이름 후보
FULL_PATH_KEYS = ("FullPath", "Path", "FilePath", "FilePath2")
FILE_NAME_KEYS = ("FileName", "Name")
UPDATE_TS_KEYS = ("UpdateTimestamp", "UpdateTime", "Timestamp")
UPDATE_REASON_KEYS = ("UpdateReasons", "Reasons")
FILE_ATTR_KEYS = ("FileAttributes", "Attributes")

# 시간 태그 기준 (버킷 길이) — 1일 / 7일 / 30일 / 30일 이후
DELTA_RECENT = timedelta(days=1)
DELTA_WEEK = timedelta(days=7)
DELTA_MONTH = timedelta(days=30)

# ──────────────────────────────────────────────────────────────
#  유틸: 컬럼 접근/타임스탬프 파싱
# ──────────────────────────────────────────────────────────────

def get_first_nonempty(row: Dict[str, Any], keys: Iterable[str]) -> str:
    for k in keys:
        v = row.get(k)
        if v:
            s = str(v).strip()
            if s:
                return s
    return ""


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    MFTECmd $J UpdateTimestamp 형식은 일반적으로
    '2025-11-27 01:02:29.1234567' 또는 유사 포맷.
    여러 포맷을 시도하고, 실패하면 None.
    """
    if not ts_str:
        return None

    s = ts_str.strip()

    candidates = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in candidates:
        try:
            dt = datetime.strptime(s, fmt)
            # 이벤트로그와 맞추기 위해 UTC 기준으로 취급
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            # 다음 포맷 시도
            continue
    return None


# ──────────────────────────────────────────────────────────────
#  분석 기준 시간: 모듈 .txt 파일명에서 추출
# ──────────────────────────────────────────────────────────────

_TIME_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2})")

def _parse_marker_time_from_name(name: str) -> Optional[datetime]:
    """
    파일명에서 'YYYY-MM-DDTHH_MM_SS' 패턴을 찾아서 UTC datetime으로 변환.
    예: '2025-12-04T02_51_03_Wannacry_Module.txt'
    """
    m = _TIME_PATTERN.search(name)
    if not m:
        return None
    ts = m.group(1)  # '2025-12-04T02_51_03'
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H_%M_%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _get_analysis_time_from_markers(base_out: Path) -> datetime:
    """
    기준:
      1) marker_dir = BASE_OUT.parent 안에서
         가장 최근 .txt 파일을 찾고, 그 파일명에서 시간을 파싱해 now로 사용
      2) 없으면 현재 UTC 시각 사용
    """
    marker_dir = base_out.parent

    txt_files: List[Path] = []
    try:
        txt_files = [p for p in marker_dir.glob("*.txt") if p.is_file()]
    except Exception:
        txt_files = []

    # 수정시간 기준 최신 순으로 정렬
    txt_files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)

    for p in txt_files:
        dt = _parse_marker_time_from_name(p.name)
        if dt is not None:
            print(f"[INFO] UsnJrnl_tag: 기준 시간(모듈 txt) -> {dt.isoformat()} ({p.name})")
            return dt

    now = datetime.now(timezone.utc)
    print(f"[INFO] UsnJrnl_tag: 모듈 txt 기준시간 없음, 현재 시각 사용 -> {now.isoformat()}")
    return now


# ──────────────────────────────────────────────────────────────
#  태깅: FORMAT_ / AREA_ / STATE_ / EVENT_ / SEC_ / ACT_ / TIME_
# ──────────────────────────────────────────────────────────────

def add_format_tags(tags: set, ext: str) -> None:
    e = ext.lower()
    if not e:
        return

    if e in DOCUMENT_EXTS:
        tags.add("FORMAT_DOCUMENT")
    if e in SPREADSHEET_EXTS:
        tags.add("FORMAT_SPREADSHEET")
    if e in PRESENTATION_EXTS:
        tags.add("FORMAT_PRESENTATION")
    if e in IMAGE_EXTS:
        tags.add("FORMAT_IMAGE")
    if e in VIDEO_EXTS:
        tags.add("FORMAT_VIDEO")
    if e in AUDIO_EXTS:
        tags.add("FORMAT_AUDIO")
    if e in ARCHIVE_EXTS:
        tags.add("FORMAT_ARCHIVE")
    if e in EXECUTABLE_EXTS:
        tags.add("FORMAT_EXECUTABLE")
    if e in SCRIPT_EXTS:
        tags.add("FORMAT_SCRIPT")
    if e in DATABASE_EXTS:
        tags.add("FORMAT_DATABASE")
    if e in LOG_EXTS:
        tags.add("FORMAT_LOG")
    if e in CONFIG_EXTS:
        tags.add("FORMAT_CONFIG")
    if e in REGISTRY_EXTS:
        tags.add("FORMAT_REGISTRY")
    if e in EMAIL_EXTS:
        tags.add("FORMAT_EMAIL")
    if e in SHORTCUT_EXTS:
        tags.add("FORMAT_SHORTCUT")


def add_area_tags(tags: set, full_path: str) -> None:
    if not full_path:
        return
    p = full_path.lower().replace("/", "\\")

    # System/Windows
    if "\\windows\\system32" in p or "\\windows\\syswow64" in p:
        tags.add("AREA_SYSTEM32")
    if "\\windows\\" in p:
        tags.add("AREA_WINDOWS")
    if "\\windows\\prefetch" in p:
        tags.add("AREA_PREFETCH")
    if "\\$recycle.bin" in p:
        tags.add("AREA_RECYCLE_BIN")
    if "\\system volume information" in p:
        tags.add("AREA_VSS")

    # Users 경로
    if "\\users\\" in p:
        if "\\desktop" in p:
            tags.add("AREA_USER_DESKTOP")
        if "\\documents" in p:
            tags.add("AREA_USER_DOCUMENTS")
        if "\\downloads" in p:
            tags.add("AREA_USER_DOWNLOADS")
        if "\\recent" in p:
            tags.add("AREA_USER_RECENT")
        if "\\appdata\\local\\low" in p:
            tags.add("AREA_APPDATA_LOCALLOW")
        elif "\\appdata\\local" in p:
            tags.add("AREA_APPDATA_LOCAL")
        if "\\appdata\\roaming" in p:
            tags.add("AREA_APPDATA_ROAMING")
        if "\\startup" in p:
            tags.add("AREA_STARTUP")

    # Program Files / ProgramData
    if "\\program files" in p:
        tags.add("AREA_PROGRAMFILES")
    if "\\programdata" in p:
        tags.add("AREA_PROGRAMDATA")

    # Temp
    if "\\temp" in p:
        tags.add("AREA_TEMP")

    # 외장 드라이브 (단순 드라이브 문자 기준)
    if len(p) >= 3 and p[1:3] == ":\\" and p[0].isalpha():
        drive_letter = p[0].upper()
        if drive_letter not in ("C",):  # C 제외
            tags.add("AREA_EXTERNAL_DRIVE")


def add_state_tags(tags: set, file_attrs: str) -> None:
    if not file_attrs:
        return
    attrs = file_attrs.lower()
    if "hidden" in attrs:
        tags.add("STATE_HIDDEN")
    if "system" in attrs:
        tags.add("STATE_SYSTEM")
    if "compressed" in attrs:
        tags.add("STATE_COMPRESSED")
    if "readonly" in attrs or "read_only" in attrs:
        tags.add("STATE_READONLY")


def add_event_and_act_tags(tags: set, reasons: str) -> None:
    """
    USN UpdateReasons 기반 EVENT_/ACT_ 태그.
    - FileCreate → EVENT_CREATE + ACT_FILE_OPERATION
    - FileDelete → EVENT_DELETE + ACT_FILE_OPERATION
    - RenameOldName / RenameNewName → EVENT_RENAME + ACT_FILE_OPERATION
    - DataExtend / DataOverwrite / DataTruncation / BasicInfoChange / NamedDataOverwrite
      → EVENT_MODIFY + ACT_FILE_OPERATION
    """
    if not reasons:
        return
    r = reasons.lower()

    # CREATE
    if "filecreate" in r:
        tags.add("EVENT_CREATE")
        tags.add("ACT_FILE_OPERATION")

    # DELETE
    if "filedelete" in r:
        tags.add("EVENT_DELETE")
        tags.add("ACT_FILE_OPERATION")

    # RENAME
    if "renameoldname" in r or "renamenewname" in r:
        tags.add("EVENT_RENAME")
        tags.add("ACT_FILE_OPERATION")

    # MODIFY (내용/속성 변경)
    modify_keywords = (
        "dataextend",
        "dataoverwrite",
        "datatruncation",
        "basicinfochange",
        "nameddataoverwrite",
    )
    if any(k in r for k in modify_keywords):
        tags.add("EVENT_MODIFY")
        tags.add("ACT_FILE_OPERATION")


def add_sec_tags(tags: set, full_path: str, file_name: str, ext: str, file_attrs: str) -> None:
    p = (full_path or "").lower()
    name = (file_name or "").lower()
    e = ext.lower()

    # 실행파일 / 스크립트
    if e in EXECUTABLE_EXTS:
        tags.add("SEC_EXECUTABLE")
    if e in SCRIPT_EXTS:
        tags.add("SEC_SCRIPT")

    # 숨김 실행파일
    if e in EXECUTABLE_EXTS and file_attrs:
        if "hidden" in file_attrs.lower():
            tags.add("SEC_HIDDEN_EXECUTABLE")

    # 의심스러운 파일명
    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in name:
            tags.add("SEC_SUSPICIOUS_NAME")
            break

    # 의심스러운 경로 (Temp/Downloads 안의 실행파일/스크립트)
    if (e in EXECUTABLE_EXTS or e in SCRIPT_EXTS):
        if "\\temp" in p or "\\downloads" in p:
            tags.add("SEC_SUSPICIOUS_PATH")

    # 이중 확장자 (예: .pdf.exe, .jpg.scr)
    lower_name = name
    for doc_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif"):
        for exec_ext in (".exe", ".scr", ".com"):
            pattern = doc_ext + exec_ext
            if lower_name.endswith(pattern):
                tags.add("SEC_SUSPICIOUS_EXTENSION")
                break


def add_time_tags(tags: set, dt: Optional[datetime], now: datetime) -> None:
    if dt is None:
        return

    diff = now - dt
    if diff <= DELTA_RECENT:
        tags.add("TIME_RECENT")
    elif diff <= DELTA_WEEK:
        tags.add("TIME_WEEK")
    elif diff <= DELTA_MONTH:
        tags.add("TIME_MONTH")
    else:
        tags.add("TIME_OLD")


# ──────────────────────────────────────────────────────────────
#  한 행 태깅 + description 생성
# ──────────────────────────────────────────────────────────────

def tag_usn_row(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """
    MFTECmd $J 한 행(row) → 태그 리스트 생성.
    """
    full_path = get_first_nonempty(row, FULL_PATH_KEYS)
    file_name = get_first_nonempty(row, FILE_NAME_KEYS)
    update_ts_str = get_first_nonempty(row, UPDATE_TS_KEYS)
    reasons = get_first_nonempty(row, UPDATE_REASON_KEYS)
    file_attrs = get_first_nonempty(row, FILE_ATTR_KEYS)

    ext = ""
    if file_name:
        idx = file_name.rfind(".")
        if idx != -1:
            ext = file_name[idx:].lower()

    dt = parse_timestamp(update_ts_str)

    tags: set[str] = set()

    # ARTIFACT 타입
    tags.add("ARTIFACT_USN_JOURNAL")

    # FORMAT_/AREA_/STATE_
    add_format_tags(tags, ext)
    add_area_tags(tags, full_path)
    add_state_tags(tags, file_attrs)

    # EVENT_/ACT_
    add_event_and_act_tags(tags, reasons)

    # SEC_
    add_sec_tags(tags, full_path, file_name, ext, file_attrs)

    # TIME_
    add_time_tags(tags, dt, now)

    return {
        "tags": sorted(tags),
        "timestamp": update_ts_str,
        "path": full_path,
        "file_name": file_name,
        "extension": ext,
        "update_reasons": reasons,
        "file_attributes": file_attrs,
    }


def build_description(row: Dict[str, Any]) -> str:
    """
    3번째 컬럼(description)에 들어갈 내용:

    "FileName : ... | Extension : ... | EventInfo : ... |
     FileAttribute : ... | USN : ... | EntryNumber : ... |
     SequenceNumber : ... | ParentEntryNumber : ... | ParentSequenceNumber : ..."
    """

    # FileName (없으면 Name)
    file_name = row.get("FileName") or row.get("Name") or ""

    # Extension (없으면 FileName에서 유추)
    extension = row.get("Extension") or ""
    if not extension and file_name:
        idx = file_name.rfind(".")
        if idx != -1:
            extension = file_name[idx:]

    # EventInfo (없으면 UpdateReasons/Reasons)
    event_info = (
        row.get("EventInfo")
        or row.get("UpdateReasons")
        or row.get("Reasons")
        or ""
    )

    # FileAttribute (없으면 FileAttributes/Attributes)
    file_attr = (
        row.get("FileAttribute")
        or row.get("FileAttributes")
        or row.get("Attributes")
        or ""
    )

    # USN (Usn / USN 둘 다 커버)
    usn_val = row.get("Usn") or row.get("USN") or ""

    entry_number = row.get("EntryNumber") or ""
    seq_number = row.get("SequenceNumber") or ""
    parent_entry = row.get("ParentEntryNumber") or ""
    parent_seq = row.get("ParentSequenceNumber") or ""

    parts: List[str] = []

    if file_name:
        parts.append(f"FileName : {file_name}")
    if extension:
        parts.append(f"Extension : {extension}")
    if event_info:
        parts.append(f"EventInfo : {event_info}")
    if file_attr:
        parts.append(f"FileAttribute : {file_attr}")
    if usn_val:
        parts.append(f"USN : {usn_val}")
    if entry_number:
        parts.append(f"EntryNumber : {entry_number}")
    if seq_number:
        parts.append(f"SequenceNumber : {seq_number}")
    if parent_entry:
        parts.append(f"ParentEntryNumber : {parent_entry}")
    if parent_seq:
        parts.append(f"ParentSequenceNumber : {parent_seq}")

    return " | ".join(parts)


# ──────────────────────────────────────────────────────────────
#  CSV → 태깅 CSV 변환 (한 파일)
# ──────────────────────────────────────────────────────────────

def _process_usn_csv_for_drive(
    csv_path: Path,
    tagged_root: Path,
    drive_tag: str,
    now: datetime,
) -> None:
    """
    MFTECmd_$J CSV 하나를 읽어서
    tagged/UsnJrnl_<드라이브>_<stem>_tagged.csv 로 저장.

    컬럼: type, time, description, tag
    """
    stem = csv_path.stem
    out_name = f"UsnJrnl_{drive_tag}_{stem}_tagged.csv"
    out_csv = tagged_root / out_name

    print(f"[USN ] 입력 CSV: {csv_path}")
    print(f"       → 출력 CSV: {out_csv}")

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)

        fieldnames = ["type", "time", "description", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        in_count = 0
        out_count = 0

        for row in reader:
            in_count += 1

            tagged_info = tag_usn_row(row, now)
            description = build_description(row)

            tags_list = tagged_info.get("tags", [])
            tag_str = "|".join(tags_list) if isinstance(tags_list, list) else str(tags_list)

            out_row = {
                "type": "usn_journal",
                "time": tagged_info.get("timestamp", ""),
                "description": description,
                "tag": tag_str,
            }
            writer.writerow(out_row)
            out_count += 1

    print(f"       행 수: 입력 {in_count} → 출력 {out_count}")


# ──────────────────────────────────────────────────────────────
#  엔트리포인트: main.py 가 호출하는 run()
# ──────────────────────────────────────────────────────────────

def run(drive_letters: List[str], cfg: Dict[str, Any]) -> bool:
    base_out: Path = cfg["BASE_OUT"]

    # Kape Output 의 상위 폴더 기준으로 tagged/ 사용
    tagged_root = base_out.parent / "tagged"
    tagged_root.mkdir(parents=True, exist_ok=True)

    # 분석 기준 시간: 모듈 txt 파일명에서 추출
    now = _get_analysis_time_from_markers(base_out)

    any_processed = False

    for dl in drive_letters:
        d = dl.rstrip(":").upper()
        # MFTECmd_$J 출력 폴더 후보
        candidates = [
            base_out / d / "MFTECmd_$J",
            base_out / f"$NFTS_{d}" / "MFTECmd_$J",
        ]

        module_roots = [c for c in candidates if c.exists()]
        if not module_roots:
            print(f"[SKIP] UsnJrnl_tag: {dl} MFTECmd_$J 출력 폴더 없음")
            continue

        target_csvs: List[Path] = []
        for root in module_roots:
            target_csvs.extend(root.rglob("*MFTECmd_$J*_Output.csv"))

        if not target_csvs:
            print(f"[SKIP] UsnJrnl_tag: {dl} MFTECmd_$J CSV 없음")
            continue

        print(f"[INFO] UsnJrnl_tag: {dl} 대상 CSV {len(target_csvs)}개")

        for csv_path in target_csvs:
            _process_usn_csv_for_drive(csv_path, tagged_root, d, now)
            any_processed = True

    if not any_processed:
        print("[INFO] UsnJrnl_tag: 처리할 USN CSV가 없습니다.")
    else:
        print("[INFO] UsnJrnl_tag: 완료")

    return any_processed
