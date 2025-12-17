#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

# ============================================================
# 0) 기본 설정 (인자 없이 F5/Ctrl+F5 누르면 자동 실행)
# ============================================================

# 1차 필터: 파일명/패턴으로 먼저 후보를 좁힘
# 필요하면 환경에 맞게 수정
TARGET_GLOB = "*AppCompatCache*.csv"

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

SUSPICIOUS_NAME_KEYWORDS = {"crack", "keygen", "payload", "backdoor", "mimikatz"}

# AppCompatCache 주요 컬럼
APPCOMPAT_TIME_KEY = "LastModifiedTimeUTC"
APPCOMPAT_DESC_KEYS = ["Path", "Executed", "Duplicate"]


# ============================================================
# 1) 유틸: timestamp 파싱 / time bucket
# ============================================================

def parse_timestamp(ts: Any) -> Optional[datetime]:
    if ts is None:
        return None
    s = str(ts).strip()
    if not s:
        return None

    # ISO8601 (Z / +00:00 등) 우선 시도
    try:
        iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        # tz-aware면 tz 제거(버킷 계산용)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except Exception:
        pass

    # microseconds 7자리 → 6자리로 줄이기
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
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def add_time_bucket_tags(tags: set, dt: Optional[datetime], now: datetime) -> None:
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
# 2) 태그: FORMAT_ / AREA_ / SEC_
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


def add_area_tags(tags: set, path_str: str) -> None:
    if not path_str:
        return
    p = path_str.lower().replace("/", "\\")

    if "\\windows\\system32" in p or "\\windows\\syswow64" in p:
        tags.add("AREA_SYSTEM32")
    if "\\windows\\" in p:
        tags.add("AREA_WINDOWS")

    if "\\users\\" in p:
        if "\\desktop" in p:
            tags.add("AREA_USER_DESKTOP")
        if "\\downloads" in p:
            tags.add("AREA_USER_DOWNLOADS")
        if "\\documents" in p:
            tags.add("AREA_USER_DOCUMENTS")
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

    # 드라이브 문자 기준 (C: 제외)
    if len(p) >= 3 and p[1:3] == ":\\" and p[0].isalpha():
        drive_letter = p[0].upper()
        if drive_letter not in ("C",):
            tags.add("AREA_EXTERNAL_DRIVE")


def add_sec_tags(tags: set, full_path: str, name: str, ext: str) -> None:
    p = (full_path or "").lower()
    lower_name = (name or "").lower()
    e = (ext or "").lower()

    if e in EXECUTABLE_EXTS:
        tags.add("SEC_EXECUTABLE")
    if e in SCRIPT_EXTS:
        tags.add("SEC_SCRIPT")

    for kw in SUSPICIOUS_NAME_KEYWORDS:
        if kw in lower_name:
            tags.add("SEC_SUSPICIOUS_NAME")
            break

    # Temp / Downloads 내 실행파일/스크립트
    if (e in EXECUTABLE_EXTS or e in SCRIPT_EXTS) and ("\\temp" in p or "\\downloads" in p):
        tags.add("SEC_SUSPICIOUS_PATH")

    # 이중 확장자
    for doc_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf",
                    ".jpg", ".jpeg", ".png", ".gif"):
        for exec_ext in (".exe", ".scr", ".com"):
            if lower_name.endswith(doc_ext + exec_ext):
                tags.add("SEC_SUSPICIOUS_EXTENSION")
                return


# ============================================================
# 3) description 생성 (Path / Executed / Duplicate)
# ============================================================

def build_appcompat_description(row: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in APPCOMPAT_DESC_KEYS:
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
# 4) CSV 스키마 판별 (fallback용)
# ============================================================

def is_appcompat_schema(fieldnames: List[str]) -> bool:
    lower = {f.lower() for f in fieldnames if f}
    required = {"path", "executed", "duplicate", "lastmodifiedtimeutc"}
    return required.issubset(lower)


# ============================================================
# 5) 한 행 태깅
# ============================================================

def tag_appcompat_row(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    raw_time = str(row.get(APPCOMPAT_TIME_KEY, "") or "").strip()
    dt = parse_timestamp(raw_time)
    ts_out = dt.strftime("%Y-%m-%d %H:%M:%S.%f") if dt is not None else raw_time

    path_val = str(row.get("Path", "") or "").strip()
    file_name = Path(path_val).name if path_val else ""
    ext = Path(file_name).suffix.lower() if file_name else ""

    tags: set = set()

    # ARTIFACT_
    tags.add("ARTIFACT_APPCOMPATCACHE")

    # 실행 여부 → EVENT_/ACT_
    executed = str(row.get("Executed", "") or "").strip().lower()
    if executed in {"yes", "true", "1"}:
        tags.add("EVENT_EXECUTED")
        tags.add("ACT_EXECUTE")

    # FORMAT_/AREA_/SEC_/TIME_
    add_format_tags(tags, ext)
    add_area_tags(tags, path_val)
    add_sec_tags(tags, path_val, file_name, ext)
    add_time_bucket_tags(tags, dt, now)

    return {
        "timestamp": ts_out,
        "description": build_appcompat_description(row),
        "tags": sorted(tags),
    }


# ============================================================
# 6) 단일 CSV 처리 (입력 1개 → 출력 1개)
# ============================================================

def process_csv(csv_path: Path, out_csv: Path, now: datetime) -> int:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in:
        reader = csv.DictReader(f_in)
        if not reader.fieldnames:
            raise ValueError("헤더 없음")

        if not is_appcompat_schema(reader.fieldnames):
            raise ValueError("AppCompatCache 스키마 아님")

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=["type", "time", "description", "tag"])
            writer.writeheader()

            out_count = 0
            for row in reader:
                tagged = tag_appcompat_row(row, now)
                tag_str = "|".join(tagged["tags"])

                writer.writerow(
                    {
                        "type": "shimcache",
                        "time": tagged["timestamp"],
                        "description": tagged["description"],
                        "tag": tag_str,
                    }
                )
                out_count += 1

    return out_count


# ============================================================
# 7) 자동 탐색 + 출력 경로 구성 + 즉시 실행(main() 호출)
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
    """
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


def _get_output_path(csv_path: Path, case_name: Optional[str]) -> Path:
    """
    출력: <드라이브>:\tagged\AppCompat_<stem>_<CASE>_tagged.csv
    """
    drive = csv_path.drive or "D:"
    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stem = csv_path.stem
    out_name = f"AppCompat_{stem}_{case_name}_tagged.csv" if case_name else f"AppCompat_{stem}_tagged.csv"
    return _ensure_unique_output_path(tagged_dir / out_name)


def _find_candidate_csvs() -> List[Path]:
    """
    1) D:~Z: 각 드라이브의 Kape Output 아래에서
       - 먼저 TARGET_GLOB 로 후보 수집
    2) 1)에서 아무것도 못 찾으면,
       - Kape Output 아래의 모든 *.csv 를 스키마로 필터링(느림)
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
        if TARGET_GLOB:
            for p in kape_root.rglob(TARGET_GLOB):
                if p.is_file():
                    glob_hits.append(p)

        # 2) fallback용 전체 csv
        for p in kape_root.rglob("*.csv"):
            if p.is_file():
                all_csvs.append(p)

    if glob_hits:
        return list({p for p in glob_hits})

    # glob로 못 찾으면 스키마 기반
    schema_hits: List[Path] = []
    for p in all_csvs:
        try:
            with p.open("r", encoding="utf-8-sig", newline="") as f:
                r = csv.reader(f)
                header = next(r, None)
                if not header:
                    continue
                if is_appcompat_schema(header):
                    schema_hits.append(p)
        except Exception:
            continue

    return list({p for p in schema_hits})


def main() -> None:
    print("[AUTO] 인자 없이 실행: D:~Z: 에서 Kape Output 아래 AppCompatCache CSV 자동 탐색")
    if TARGET_GLOB:
        print(f"[AUTO] 1차 필터: {TARGET_GLOB}")
    else:
        print("[AUTO] 1차 필터 없음: 스키마 기반으로만 탐색")

    candidates = _find_candidate_csvs()
    if not candidates:
        print("[END] 대상 CSV 없음")
        return

    print(f"[AUTO] 대상 CSV {len(candidates)}개 발견")

    # 인자 없이 실행이므로 now는 현재 시각으로 고정
    now = datetime.now()

    for csv_path in sorted(candidates):
        case_name = _get_case_name(csv_path)
        out_path = _get_output_path(csv_path, case_name)

        print(f"\n[+] Input : {csv_path}")
        print(f"[+] Output: {out_path}")

        try:
            rows = process_csv(csv_path, out_path, now)
            print(f"[OK] rows={rows}")
        except Exception as e:
            print(f"[SKIP] 처리 실패: {e}")


# ✅ F5/Ctrl+F5 누르면 무조건 실행
if __name__ == "__main__":
    main()
