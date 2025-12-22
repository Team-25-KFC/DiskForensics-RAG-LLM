#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
from datetime import datetime, timedelta

# ============================================================
# 0) 기본 설정 (인자 없이 F5 누르면 자동 실행)
# ============================================================

# 1차 필터: 파일명 접미사로 먼저 후보를 좁힘 (없으면 스키마로 2차 필터)
# MFTECmd $J(USN) 기본 출력명 관례: 20251205050803_MFTECmd_$J_Output.csv
TARGET_SUFFIX = "_MFTECmd_$J_Output.csv"

# 시간 태그 버킷
DELTA_RECENT = timedelta(days=1)
DELTA_WEEK = timedelta(days=7)
DELTA_MONTH = timedelta(days=30)

# 확장자 분류
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


# ============================================================
# 1) 유틸: 컬럼 접근 / timestamp 파싱 / time bucket
# ============================================================

def get_first_nonempty(row: Dict[str, Any], keys: Iterable[str]) -> str:
    for k in keys:
        v = row.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def parse_timestamp(ts_str: Any) -> Optional[datetime]:
    """
    USN Timestamp 표준화:
    - 입력 예:
        '2025-11-27 01:02:29.1234567'
        '2025-11-27 01:02:29'
        '2025-11-27T01:02:29.1234567'
        '2025-11-27T01:02:29'
    - 7자리 microseconds → 6자리로 줄여서 파싱
    - 반환: 로컬 기준 naive datetime
    """
    if ts_str is None:
        return None
    s = str(ts_str).strip()
    if not s:
        return None

    # 7자리 microseconds → 6자리로 통일
    m = re.search(r"\.(\d{6,7})$", s)
    if m:
        micro = m.group(1)
        if len(micro) == 7:
            s = s.replace("." + micro, "." + micro[:6])

    candidates = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def add_time_bucket_tags(tags: set, dt: Optional[datetime], now: datetime) -> None:
    """
    now - dt 기준 TIME_* 버킷 태그
    """
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


# ============================================================
# 2) 태그: FORMAT_ / AREA_ / STATE_ / EVENT_ / ACT_ / SEC_
# ============================================================

def add_format_tags(tags: set, ext: str) -> None:
    e = (ext or "").lower()
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

    if "filecreate" in r:
        tags.add("EVENT_CREATE")
        tags.add("ACT_FILE_OPERATION")

    if "filedelete" in r:
        tags.add("EVENT_DELETE")
        tags.add("ACT_FILE_OPERATION")

    if "renameoldname" in r or "renamenewname" in r:
        tags.add("EVENT_RENAME")
        tags.add("ACT_FILE_OPERATION")

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
    e = (ext or "").lower()

    if e in EXECUTABLE_EXTS:
        tags.add("SEC_EXECUTABLE")
    if e in SCRIPT_EXTS:
        tags.add("SEC_SCRIPT")

    if e in EXECUTABLE_EXTS and file_attrs and ("hidden" in file_attrs.lower()):
        tags.add("SEC_HIDDEN_EXECUTABLE")

    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in name:
            tags.add("SEC_SUSPICIOUS_NAME")
            break

    if (e in EXECUTABLE_EXTS or e in SCRIPT_EXTS) and ("\\temp" in p or "\\downloads" in p):
        tags.add("SEC_SUSPICIOUS_PATH")

    # 이중 확장자 (예: .pdf.exe, .jpg.scr)
    lower_name = name
    for doc_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif"):
        for exec_ext in (".exe", ".scr", ".com"):
            if lower_name.endswith(doc_ext + exec_ext):
                tags.add("SEC_SUSPICIOUS_EXTENSION")
                return


# ============================================================
# 3) description 생성
# ============================================================

def build_description(row: Dict[str, Any]) -> str:
    """
    3번째 컬럼(description):
      "FileName : ... | Extension : ... | EventInfo : ... |
       FileAttribute : ... | USN : ... | EntryNumber : ... |
       SequenceNumber : ... | ParentEntryNumber : ... | ParentSequenceNumber : ..."
    """
    file_name = row.get("FileName") or row.get("Name") or ""

    extension = row.get("Extension") or ""
    if not extension and file_name:
        idx = str(file_name).rfind(".")
        if idx != -1:
            extension = str(file_name)[idx:]

    event_info = row.get("EventInfo") or row.get("UpdateReasons") or row.get("Reasons") or ""
    file_attr = row.get("FileAttribute") or row.get("FileAttributes") or row.get("Attributes") or ""
    usn_val = row.get("Usn") or row.get("USN") or ""

    entry_number = row.get("EntryNumber") or ""
    seq_number = row.get("SequenceNumber") or ""
    parent_entry = row.get("ParentEntryNumber") or ""
    parent_seq = row.get("ParentSequenceNumber") or ""

    parts: List[str] = []
    if file_name:
        parts.append(f"FileName : {str(file_name).strip()}")
    if extension:
        parts.append(f"Extension : {str(extension).strip()}")
    if event_info:
        parts.append(f"EventInfo : {str(event_info).strip()}")
    if file_attr:
        parts.append(f"FileAttribute : {str(file_attr).strip()}")
    if usn_val:
        parts.append(f"USN : {str(usn_val).strip()}")
    if entry_number:
        parts.append(f"EntryNumber : {str(entry_number).strip()}")
    if seq_number:
        parts.append(f"SequenceNumber : {str(seq_number).strip()}")
    if parent_entry:
        parts.append(f"ParentEntryNumber : {str(parent_entry).strip()}")
    if parent_seq:
        parts.append(f"ParentSequenceNumber : {str(parent_seq).strip()}")

    return " | ".join(parts)


# ============================================================
# 4) CSV 스키마 판별 (USN)
# ============================================================

def is_usn_schema(fieldnames: List[str]) -> bool:
    lower = {f.lower() for f in fieldnames}

    def has_any(keys: Iterable[str]) -> bool:
        return any(k.lower() in lower for k in keys)

    # 필수: Timestamp + Reasons + FileName(또는 Name)
    if not has_any(UPDATE_TS_KEYS):
        return False
    if not has_any(UPDATE_REASON_KEYS):
        return False
    if not has_any(FILE_NAME_KEYS):
        return False

    # 추가 힌트(둘 중 하나라도 있으면 더 확실)
    path_hint = has_any(FULL_PATH_KEYS) or ("parentpath" in lower) or ("directory" in lower)
    id_hint = ("entrynumber" in lower) or ("sequencenumber" in lower) or ("usn" in lower) or ("frn" in lower)

    return path_hint or id_hint



# ============================================================
# 5) 한 행 태깅 (USN)
# ============================================================

def tag_usn_row(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
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

    # ARTIFACT
    tags.add("ARTIFACT_USN_JOURNAL")

    # FORMAT_/AREA_/STATE_
    add_format_tags(tags, ext)
    add_area_tags(tags, full_path)
    add_state_tags(tags, file_attrs)

    # EVENT_/ACT_
    add_event_and_act_tags(tags, reasons)

    # SEC_
    add_sec_tags(tags, full_path, file_name, ext, file_attrs)

    # TIME_*
    add_time_bucket_tags(tags, dt, now)

    ts_out = dt.strftime("%Y-%m-%d %H:%M:%S.%f") if dt is not None else (str(update_ts_str).strip() if update_ts_str else "")

    return {
        "tags": sorted(tags),
        "timestamp": ts_out,
    }


# ============================================================
# 6) 단일 CSV 처리 (입력 1개 → 출력 1개)
# ============================================================

def process_csv(csv_path: Path, out_csv: Path, now: datetime) -> int:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in:
        reader = csv.DictReader(f_in)
        if not reader.fieldnames:
            raise ValueError("헤더 없음")

        if not is_usn_schema(reader.fieldnames):
            raise ValueError("USN($J) 스키마 아님")

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:
            fieldnames = ["type", "time", "description", "tag"]
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            out_count = 0
            for row in reader:
                info = tag_usn_row(row, now)
                desc = build_description(row)
                tag_str = "|".join(info["tags"]) if isinstance(info["tags"], list) else str(info["tags"])

                writer.writerow(
                    {
                        "type": "usn_journal",
                        "time": info["timestamp"],
                        "description": desc,
                        "tag": tag_str,
                    }
                )
                out_count += 1

    return out_count


# ============================================================
# 7) 기준 시간(now) 추출: 모듈 txt 파일명 타임스탬프
# ============================================================

_TIME_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2})"), "%Y-%m-%dT%H_%M_%S"),
    (re.compile(r"(\d{14})"), "%Y%m%d%H%M%S"),
]


def _parse_marker_time_from_name(name: str) -> Optional[datetime]:
    for pattern, fmt in _TIME_PATTERNS:
        m = pattern.search(name)
        if not m:
            continue
        ts = m.group(1)
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _get_analysis_time_from_root(root: Path, label: str) -> datetime:
    """
    root 아래에서
      1) *_Module.txt / *ConsoleLog*.txt 우선
      2) 없으면 *.txt 전체
      3) 최신 mtime 순으로 파일명 timestamp 파싱
      4) 성공 시 그 시간, 실패 시 datetime.now()
    """
    candidates: List[Path] = []
    try:
        candidates = [p for p in root.rglob("*_Module.txt") if p.is_file()]
        candidates += [p for p in root.rglob("*ConsoleLog*.txt") if p.is_file()]
    except Exception:
        candidates = []

    # 중복 제거
    seen = set()
    uniq: List[Path] = []
    for c in candidates:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    candidates = uniq

    if not candidates:
        try:
            candidates = [p for p in root.rglob("*.txt") if p.is_file()]
        except Exception:
            candidates = []

    if not candidates:
        now = datetime.now()
        print(f"[INFO] UsnJrnl_tag: {label} 기준 txt 없음, 현재 시각 사용 -> {now.isoformat()}")
        return now

    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)

    for p in candidates:
        dt = _parse_marker_time_from_name(p.name)
        if dt is not None:
            print(f"[INFO] UsnJrnl_tag: {label} 기준 시간(모듈 txt) -> {dt.isoformat()} ({p})")
            return dt

    now = datetime.now()
    print(f"[INFO] UsnJrnl_tag: {label} 파일명에서 시간 파싱 실패, 현재 시각 사용 -> {now.isoformat()}")
    return now


def _get_evidence_drive_root(csv_path: Path) -> Optional[Path]:
    r"""
    ...\MFTECmd_$J\<something>_Output.csv 라면,
    evidence_drive_root = MFTECmd_$J의 부모 (예: $NFTS_G 또는 G)
    """
    parts = [p for p in csv_path.parts]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].lower() == "mftecmd_$j":
            if i - 1 >= 0:
                # 부모 폴더(증거 드라이브 루트)
                return Path(*parts[:i])  # ...\<parent_of_MFTECmd_$J>
    # 못 찾으면 폴더 기준으로 한 단계 위에서라도
    try:
        return csv_path.parent
    except Exception:
        return None


def _infer_evidence_drive_tag(csv_path: Path) -> str:
    """
    MFTECmd_$J 부모 폴더명을 기반으로 드라이브 태그 추론:
      - $NFTS_G  -> G
      - G        -> G
    실패 시 물리 드라이브 문자(csv_path.drive)에서 추출 (예: D:)
    """
    parts = [p for p in csv_path.parts]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].lower() == "mftecmd_$j":
            if i - 1 >= 0:
                parent = parts[i - 1]
                m = re.fullmatch(r"\$NFTS_([A-Za-z])", parent)
                if m:
                    return m.group(1).upper()
                if re.fullmatch(r"[A-Za-z]", parent):
                    return parent.upper()
            break

    drv = (csv_path.drive or "").replace(":", "").upper()
    return drv if re.fullmatch(r"[A-Z]", drv) else "X"


# ============================================================
# 8) 자동 탐색 + 출력 경로 구성 + 즉시 실행(main() 호출)
# ============================================================

def _find_kape_output_root(drive_root: Path) -> Optional[Path]:
    cand1 = drive_root / "Kape Output"
    if cand1.exists():
        return cand1
    cand2 = drive_root / "KAPE Output"
    if cand2.exists():
        return cand2
    return None


def _get_case_name(csv_path: Path) -> Optional[str]:
    r"""
    <드라이브>:\Kape Output\<CASE>\...\file.csv 에서 <CASE> 추출
    """
    p = csv_path
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None
            return rel.parts[0] if rel.parts else None
    return None


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


def _get_output_path(csv_path: Path, drive_tag: str, case_name: Optional[str]) -> Path:
    r"""
    출력:
      <물리드라이브>:\tagged\UsnJrnl_<drive_tag>_<stem>_<CASE>_tagged.csv
      (CASE 없으면 <CASE> 부분 생략)
    """
    drive = csv_path.drive or "D:"
    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stem = csv_path.stem
    if case_name:
        out_name = f"UsnJrnl_{drive_tag}_{stem}_{case_name}_tagged.csv"
    else:
        out_name = f"UsnJrnl_{drive_tag}_{stem}_tagged.csv"

    return _ensure_unique_output_path(tagged_dir / out_name)


def _find_candidate_csvs() -> List[Path]:
    """
    1) D:~Z: 각 드라이브의 Kape Output 아래에서
       - 먼저 *TARGET_SUFFIX 로 후보 수집
    2) 1)에서 아무것도 못 찾으면,
       - Kape Output 아래의 모든 *.csv 를 스키마로 필터링
    """
    suffix_hits: List[Path] = []
    all_csvs: List[Path] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = _find_kape_output_root(drive_root)
        if not kape_root:
            continue

        # 1) suffix 기반
        if TARGET_SUFFIX:
            for p in kape_root.rglob(f"*{TARGET_SUFFIX}"):
                if p.is_file():
                    suffix_hits.append(p)

        # 2) fallback용 전체 csv
        for p in kape_root.rglob("*.csv"):
            if p.is_file():
                all_csvs.append(p)

    if suffix_hits:
        return suffix_hits

    # suffix로 못 찾으면 스키마 기반으로 좁히기
    schema_hits: List[Path] = []
    for p in all_csvs:
        try:
            with p.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue
                if is_usn_schema(header):
                    schema_hits.append(p)
        except Exception:
            continue

    return schema_hits


def main() -> None:
    print("[AUTO] 인자 없이 실행: D:~Z: 에서 Kape Output 아래 USN($J) CSV 자동 탐색")
    if TARGET_SUFFIX:
        print(f"[AUTO] 1차 필터: *{TARGET_SUFFIX}")
    else:
        print("[AUTO] 1차 필터 없음: 스키마 기반으로만 탐색")

    candidates = _find_candidate_csvs()
    if not candidates:
        print("[END] 대상 CSV 없음")
        return

    print(f"[AUTO] 대상 CSV {len(candidates)}개 발견")

    for csv_path in candidates:
        case_name = _get_case_name(csv_path)
        evidence_drive_tag = _infer_evidence_drive_tag(csv_path)

        evidence_root = _get_evidence_drive_root(csv_path)
        if evidence_root and evidence_root.exists():
            now = _get_analysis_time_from_root(evidence_root, f"{evidence_drive_tag}")
        else:
            now = datetime.now()
            print(f"[INFO] UsnJrnl_tag: 기준 루트 탐지 실패, 현재 시각 사용 -> {now.isoformat()} ({csv_path})")

        out_path = _get_output_path(csv_path, evidence_drive_tag, case_name)

        print(f"\n[+] Input : {csv_path}")
        print(f"[+] Output: {out_path}")

        try:
            rows = process_csv(csv_path, out_path, now)
            print(f"[OK] rows={rows}")
        except Exception as e:
            print(f"[SKIP] 처리 실패: {e}")


# ✅ 파일 자체가 “존재만으로 실행”되게: F5 누르면 무조건 실행
if __name__ == "__main__":
    main()
