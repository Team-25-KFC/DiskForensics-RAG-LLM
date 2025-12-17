#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
INDXRipper($I30) CSV를 입력으로 받아
type / time / description / tag 형식으로 변환하는 모듈.

- Ctrl+F5(인자 없이 실행) 지원:
  D:~Z: 드라이브의 "Kape Output"/"KAPE Output" 아래에서
  *INDXRipper*.csv 를 자동 탐색해 처리한다.

- time bucket(TIME_RECENT/WEEK/MONTH/OLD)의 기준시각(now)은
  ✅ "해당 CSV 내용에서 파싱 가능한 타임스탬프들의 최댓값"으로 잡는다.
  (즉, 다른 모듈 로그/최신 파일 mtime 같은 외부 기준은 쓰지 않는다.)

- 출력:
  <물리드라이브>:\\tagged\\INDX_<vol_tag>_<stem>_tagged.csv
"""

import re
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

# ============================================================
# 0) 기본 설정 (인자 없이 Ctrl+F5 누르면 자동 실행)
# ============================================================

SCAN_DRIVE_FROM = "D"
SCAN_DRIVE_TO = "Z"
KAPE_DIR_NAMES = ("Kape Output", "KAPE Output")

TARGET_GLOBS = (
    "*INDXRipper*All*.csv",
    "*INDXRipper*.csv",
)

# TIME_ 버킷
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

SUSPICIOUS_NAME_KEYWORDS = {"crack", "keygen", "payload", "backdoor", "mimikatz"}

# description keys
INDX_DESC_KEYS: List[str] = [
    "Source",
    "ParentPath",
    "Filename",
    "Flags",
    "Size",
    "CreationTime",
    "ModificationTime",
    "AccessTime",
    "ChangedTime",
]

# CSV에서 now를 만들 때 사용할 후보 시간 컬럼들(있을 때만 사용)
NOW_TIME_KEYS = ["AccessTime", "CreationTime", "ModificationTime", "ChangedTime"]

# ============================================================
# 1) 유틸: timestamp 파싱 / time bucket
# ============================================================

def parse_timestamp(ts_str: Any) -> Optional[datetime]:
    """
    INDXRipper 타임스탬프 파싱용.
    - 1601-01-01... 은 '시간 없음'으로 보고 None
    - 소수점 7자리 → 6자리로 잘라서 처리
    - T/공백, 타임존(+00:00) 등 여러 포맷 지원
    """
    if ts_str is None:
        return None
    s = str(ts_str).strip()
    if not s:
        return None

    if s.startswith("1601-01-01"):
        return None

    m = re.search(r"\.(\d{6,7})", s)
    if m:
        micro = m.group(1)
        if len(micro) == 7:
            s = s.replace("." + micro, "." + micro[:6])

    fmts = [
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


def add_time_bucket_tags(tags: set, dt: Optional[datetime], now: Optional[datetime]) -> None:
    """
    now - dt 기준 TIME_* 버킷 태그
    (now는 '해당 CSV 내용'에서 뽑은 최댓값)
    """
    if dt is None or now is None:
        return
    if dt > now:
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


def add_time_presence_tags(tags: set, row: Dict[str, Any]) -> None:
    ct = parse_timestamp(row.get("CreationTime", ""))
    mt = parse_timestamp(row.get("ModificationTime", ""))
    at = parse_timestamp(row.get("AccessTime", ""))

    if ct is not None:
        tags.add("TIME_CREATED")
    if mt is not None:
        tags.add("TIME_MODIFIED")
    if at is not None:
        tags.add("TIME_ACCESSED")

# ============================================================
# 2) 태그: FORMAT_ / AREA_ / SEC_ / STATE_ / EVENT_
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

    if "\\windows\\system32" in p or "\\windows\\syswow64" in p:
        tags.add("AREA_SYSTEM32")
    if "\\windows\\" in p:
        tags.add("AREA_WINDOWS")

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

    if "\\program files" in p:
        tags.add("AREA_PROGRAMFILES")
    if "\\programdata" in p:
        tags.add("AREA_PROGRAMDATA")

    if "\\temp" in p:
        tags.add("AREA_TEMP")
    if "\\$recycle.bin" in p:
        tags.add("AREA_RECYCLE_BIN")
    if "\\system volume information" in p:
        tags.add("AREA_VSS")

    # 드라이브 문자 기반 외장 드라이브 추정(C: 제외)
    if len(p) >= 3 and p[1:3] == ":\\" and p[0].isalpha():
        drive_letter = p[0].upper()
        if drive_letter not in ("C",):
            tags.add("AREA_EXTERNAL_DRIVE")


def add_sec_tags(tags: set, full_path: str, file_name: str, ext: str, flags: str) -> None:
    p = (full_path or "").lower()
    name = (file_name or "").lower()
    e = (ext or "").lower()
    flags_l = (flags or "").lower()

    if e in EXECUTABLE_EXTS:
        tags.add("SEC_EXECUTABLE")
    if e in SCRIPT_EXTS:
        tags.add("SEC_SCRIPT")

    if e in EXECUTABLE_EXTS and "hidden" in flags_l:
        tags.add("SEC_HIDDEN_EXECUTABLE")

    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in name:
            tags.add("SEC_SUSPICIOUS_NAME")
            break

    if (e in EXECUTABLE_EXTS or e in SCRIPT_EXTS) and ("\\temp" in p or "\\downloads" in p):
        tags.add("SEC_SUSPICIOUS_PATH")

    # 이중 확장자(.pdf.exe, .jpg.scr 등)
    for doc_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf",
                    ".jpg", ".jpeg", ".png", ".gif"):
        for exec_ext in (".exe", ".scr", ".com"):
            if name.endswith(doc_ext + exec_ext):
                tags.add("SEC_SUSPICIOUS_EXTENSION")
                return


def add_state_tags(tags: set, source: str, flags: str) -> None:
    s = (source or "").lower()
    f = (flags or "").lower()

    if "slack" in s:
        tags.add("STATE_SLACK_SPACE")
    else:
        tags.add("STATE_ACTIVE")

    if "hidden" in f:
        tags.add("STATE_HIDDEN")
    if "readonly" in f or "read-only" in f:
        tags.add("STATE_READONLY")
    if "system" in f:
        tags.add("STATE_SYSTEM")


def add_event_tags(tags: set, row: Dict[str, Any]) -> None:
    joined = " ".join("" if v is None else str(v) for v in row.values()).lower()
    if "delete" in joined or "deleted" in joined:
        tags.add("EVENT_DELETE")
    if "create" in joined or "created" in joined:
        tags.add("EVENT_CREATE")

# ============================================================
# 3) description / full path
# ============================================================

def build_indx_full_path(row: Dict[str, Any]) -> str:
    parent = str(row.get("ParentPath", "") or "").strip()
    name = str(row.get("Filename", "") or "").strip()
    if parent and name:
        if parent.endswith("\\") or parent.endswith("/"):
            return parent + name
        return parent + "\\" + name
    return name or parent


def build_indx_description(row: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in INDX_DESC_KEYS:
        if key not in row:
            continue
        v = row.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        parts.append(f"{key} : {s}")
    return " | ".join(parts)

# ============================================================
# 4) CSV 스키마 판별 (fallback)
# ============================================================

def is_indxripper_schema(fieldnames: List[str]) -> bool:
    lower = {f.lower() for f in fieldnames}
    required = {"parentpath", "filename"}
    if not required.issubset(lower):
        return False

    time_keys = {"accesstime", "creationtime", "modificationtime", "changedtime"}
    if not (lower & time_keys):
        return False

    return True

# ============================================================
# 5) "해당 CSV"에서 now(기준시각) 산출
# ============================================================

def infer_now_from_csv(csv_path: Path) -> Optional[datetime]:
    """
    ✅ 외부 로그/mtime 없이, 오직 해당 CSV 내용만으로 now를 만든다.
    - 후보 컬럼(NOW_TIME_KEYS)에서 파싱 가능한 datetime들의 최댓값을 반환
    - 전혀 파싱되는 값이 없으면 None 반환 (버킷 태그는 생략됨)
    """
    max_dt: Optional[datetime] = None

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return None

        usable_keys = [k for k in NOW_TIME_KEYS if k in reader.fieldnames]
        if not usable_keys:
            return None

        for row in reader:
            for k in usable_keys:
                dt = parse_timestamp(row.get(k, ""))
                if dt is None:
                    continue
                if (max_dt is None) or (dt > max_dt):
                    max_dt = dt

    return max_dt

# ============================================================
# 6) 한 행 태깅
# ============================================================

def tag_indx_row(row: Dict[str, Any], now: Optional[datetime]) -> Dict[str, Any]:
    raw_time = str(row.get("AccessTime", "") or "").strip()
    dt_access = parse_timestamp(raw_time)

    if dt_access is not None:
        ts_out = dt_access.strftime("%Y-%m-%d %H:%M:%S.%f")
    else:
        ts_out = raw_time

    full_path = build_indx_full_path(row)
    file_name = str(row.get("Filename", "") or "").strip()

    ext = ""
    if file_name:
        idx = file_name.rfind(".")
        if idx != -1:
            ext = file_name[idx:].lower()

    source = str(row.get("Source", "") or "")
    flags = str(row.get("Flags", "") or "")

    tags: set[str] = set()

    tags.add("ARTIFACT_$I30")

    add_state_tags(tags, source, flags)
    add_format_tags(tags, ext)
    add_area_tags(tags, full_path)
    add_sec_tags(tags, full_path, file_name, ext, flags)

    # TIME_ 버킷은 "CSV에서 뽑은 now"로만 계산
    add_time_bucket_tags(tags, dt_access, now)

    # TIME_* 존재 여부
    add_time_presence_tags(tags, row)

    # EVENT_
    add_event_tags(tags, row)

    return {
        "timestamp": ts_out,
        "description": build_indx_description(row),
        "tags": sorted(tags),
    }

# ============================================================
# 7) 단일 CSV 처리 (입력 1개 → 출력 1개)
# ============================================================

def process_csv(csv_path: Path, out_csv: Path, now: Optional[datetime]) -> int:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in:
        reader = csv.DictReader(f_in)
        if not reader.fieldnames:
            raise ValueError("헤더 없음")

        if not is_indxripper_schema(reader.fieldnames):
            raise ValueError("INDXRipper 스키마 아님")

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:
            fieldnames = ["type", "time", "description", "tag"]
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            out_count = 0
            for row in reader:
                tagged = tag_indx_row(row, now)
                tag_str = "|".join(tagged["tags"])
                writer.writerow(
                    {
                        "type": "$I30",
                        "time": tagged["timestamp"],
                        "description": tagged["description"],
                        "tag": tag_str,
                    }
                )
                out_count += 1

    return out_count

# ============================================================
# 8) 자동 탐색 + 출력 경로 구성 + 즉시 실행(main() 호출)
# ============================================================

def _find_kape_output_root(drive_root: Path) -> Optional[Path]:
    for name in KAPE_DIR_NAMES:
        cand = drive_root / name
        if cand.exists() and cand.is_dir():
            return cand
    return None


def _infer_vol_tag_from_path(csv_path: Path) -> str:
    """
    출력 파일명에 넣을 vol_tag 추정:
    - 경로 파트 중 "$NFTS_X"가 있으면 X
    - 경로 파트 중 "X"(단일 문자 디렉터리)가 있으면 X
    - 없으면 csv가 있는 물리 드라이브 문자
    """
    parts = list(csv_path.parts)

    for part in parts:
        up = part.upper()
        if up.startswith("$NFTS_") and len(up) == 6 and up[-1].isalpha():
            return up[-1]

    for part in parts:
        if len(part) == 1 and part.isalpha():
            return part.upper()

    drv = (csv_path.drive or "").upper()
    if drv and drv[0].isalpha():
        return drv[0]

    return "X"


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


def _get_output_path(csv_path: Path, vol_tag: str) -> Path:
    """
    출력: <물리드라이브>:\\tagged\\INDX_<vol_tag>_<stem>_tagged.csv
    """
    drive = csv_path.drive or "D:"
    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stem = csv_path.stem
    out_name = f"INDX_{vol_tag}_{stem}_tagged.csv"
    return _ensure_unique_output_path(tagged_dir / out_name)


def _find_candidate_csvs() -> List[Path]:
    """
    1) D:~Z: 각 드라이브의 Kape Output 아래에서 TARGET_GLOBS로 후보 수집
    2) 1)에서 없으면 Kape Output 아래 모든 *.csv를 스키마로 필터링
    """
    hits_by_name: List[Path] = []
    all_csvs: List[Path] = []

    for drive_code in range(ord(SCAN_DRIVE_FROM), ord(SCAN_DRIVE_TO) + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = _find_kape_output_root(drive_root)
        if not kape_root:
            continue

        for pat in TARGET_GLOBS:
            for p in kape_root.rglob(pat):
                if p.is_file():
                    hits_by_name.append(p)

        for p in kape_root.rglob("*.csv"):
            if p.is_file():
                all_csvs.append(p)

    if hits_by_name:
        return sorted({p for p in hits_by_name})

    schema_hits: List[Path] = []
    for p in all_csvs:
        try:
            with p.open("r", encoding="utf-8-sig", newline="") as f:
                r = csv.reader(f)
                header = next(r, None)
                if not header:
                    continue
                if is_indxripper_schema(header):
                    schema_hits.append(p)
        except Exception:
            continue

    return sorted({p for p in schema_hits})


def main() -> None:
    print(f"[AUTO] 인자 없이 실행: {SCAN_DRIVE_FROM}:~{SCAN_DRIVE_TO}: 에서 Kape Output 아래 INDXRipper CSV 자동 탐색")
    print(f"[AUTO] 1차 필터: {', '.join(TARGET_GLOBS)} (없으면 스키마 기반 2차 필터)")

    candidates = _find_candidate_csvs()
    if not candidates:
        print("[END] 대상 CSV 없음")
        return

    print(f"[AUTO] 대상 CSV {len(candidates)}개 발견")

    for csv_path in candidates:
        vol_tag = _infer_vol_tag_from_path(csv_path)
        out_path = _get_output_path(csv_path, vol_tag)

        # ✅ now는 "해당 CSV 내용"에서만 산출
        now = infer_now_from_csv(csv_path)
        if now is not None:
            print(f"[INFO] INDX_tag: 기준 시간(now) = CSV 내 최댓값 -> {now.isoformat()}")
        else:
            print("[INFO] INDX_tag: CSV에서 파싱 가능한 now를 만들지 못함 -> TIME_RECENT/WEEK/MONTH/OLD 생략")

        print(f"\n[+] Input : {csv_path}")
        print(f"[+] Output: {out_path}")

        try:
            rows = process_csv(csv_path, out_path, now)
            print(f"[OK] rows={rows}")
        except Exception as e:
            print(f"[SKIP] 처리 실패: {e}")


if __name__ == "__main__":
    main()
