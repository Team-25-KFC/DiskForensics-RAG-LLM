#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable, Tuple
from datetime import datetime, timedelta

# ============================================================
# 0) 기본 설정 (인자 없이 F5 누르면 자동 실행)
# ============================================================

# 1차 필터: 파일명 접미사로 먼저 후보를 좁힘 (없으면 스키마로 2차 필터)
# 필요하면 너가 파일명에 맞게 바꿔도 됨.
TARGET_SUFFIX = "_SBECmd_Output.csv"

# 시간 태그 버킷
DELTA_RECENT = timedelta(days=1)
DELTA_WEEK = timedelta(days=7)
DELTA_MONTH = timedelta(days=30)

# 확장자 분류(필요 시 유지/확장)
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

# ============================================================
# 1) 유틸: timestamp 파싱 / time bucket
# ============================================================

def parse_timestamp(ts: Any) -> Optional[datetime]:
    """
    예:
      '2025-12-05 2:28'
      '2024-04-11 14:27:30'
      '2024-04-11 14:27:30.123456'
    """
    if ts is None:
        return None
    s = str(ts).strip()
    if not s:
        return None

    # microseconds 7자리 → 6자리로 줄이기 (있다면)
    m = re.search(r"\.(\d{6,7})$", s)
    if m:
        micro = m.group(1)
        if len(micro) == 7:
            s = s.replace("." + micro, "." + micro[:6])

    candidates = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
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

    if e in EXECUTABLE_EXTS or e in SCRIPT_EXTS:
        if "\\temp" in p or "\\downloads" in p:
            tags.add("SEC_SUSPICIOUS_PATH")

    # 이중 확장자
    for doc_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif"):
        for exec_ext in (".exe", ".scr", ".com"):
            if lower_name.endswith(doc_ext + exec_ext):
                tags.add("SEC_SUSPICIOUS_EXTENSION")
                return


# ============================================================
# 3) ShellBags(예시) 시간 선택 규칙
# ============================================================

def pick_shellbags_time(row: Dict[str, Any]) -> Optional[datetime]:
    """
    우선순위:
      1) LastInteracted
      2) FirstInteracted
      3) LastWriteTime
      4) AccessedOn
    """
    dt = parse_timestamp(row.get("LastInteracted", ""))
    if dt is not None:
        return dt

    dt = parse_timestamp(row.get("FirstInteracted", ""))
    if dt is not None:
        return dt

    dt = parse_timestamp(row.get("LastWriteTime", ""))
    if dt is not None:
        return dt

    dt = parse_timestamp(row.get("AccessedOn", ""))
    if dt is not None:
        return dt

    return None


# ============================================================
# 4) description 생성
# ============================================================

def build_description(row: Dict[str, Any]) -> str:
    fields_order = [
        ("AbsolutePath", "AbsolutePath"),
        ("Value", "Value"),
        ("ShellType", "ShellType"),
        ("CreatedOn", "CreatedOn"),
        ("ModifiedOn", "ModifiedOn"),
        ("AccessedOn", "AccessedOn"),
        ("LastWriteTime", "LastWriteTime"),
        ("FirstInteracted", "FirstInteracted"),
        ("LastInteracted", "LastInteracted"),
        ("HasExplored", "HasExplored"),
        ("BagPath", "BagPath"),
        ("Miscellaneous", "Miscellaneous"),
    ]

    parts: List[str] = []
    for col_name, label in fields_order:
        v = row.get(col_name)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            parts.append(f"{label} : {s}")

    return " | ".join(parts)


# ============================================================
# 5) CSV 스키마 판별
# ============================================================

def is_shellbags_schema(fieldnames: List[str]) -> bool:
    lower = {f.lower() for f in fieldnames}
    required = {"bagpath", "absolutepath"}
    if not required.issubset(lower):
        return False

    time_candidates = {
        "createdon",
        "modifiedon",
        "accessedon",
        "lastwritetime",
        "firstinteracted",
        "lastinteracted",
    }
    if not (lower & time_candidates):
        return False

    return True


# ============================================================
# 6) 한 행 태깅
# ============================================================

def tag_shellbags_row(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    bag_path = row.get("BagPath", "")
    absolute_path = row.get("AbsolutePath", "")
    shell_type = row.get("ShellType", "")
    value = row.get("Value", "")

    name_candidate = str(value or "").strip() or str(absolute_path or "").strip()

    ext = ""
    if name_candidate:
        idx = name_candidate.rfind(".")
        if idx != -1:
            ext = name_candidate[idx:].lower()

    tags: set[str] = set()

    # ARTIFACT
    tags.add("ARTIFACT_SHELLBAG")

    # AREA_ / FORMAT_ / SEC_
    add_area_tags(tags, absolute_path)
    add_format_tags(tags, ext)
    add_sec_tags(tags, absolute_path, name_candidate, ext)

    # TIME_*
    dt = pick_shellbags_time(row)
    if dt is not None:
        add_time_bucket_tags(tags, dt, now)

    ts_out = dt.strftime("%Y-%m-%d %H:%M:%S") if dt is not None else ""

    return {
        "tags": sorted(tags),
        "timestamp": ts_out,
        "bag_path": bag_path,
        "absolute_path": absolute_path,
        "shell_type": shell_type,
        "value": value,
    }


# ============================================================
# 7) 단일 CSV 처리 (입력 1개 → 출력 1개)
# ============================================================

def process_csv(csv_path: Path, out_csv: Path, now: datetime) -> int:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in:
        reader = csv.DictReader(f_in)
        if not reader.fieldnames:
            raise ValueError("헤더 없음")

        if not is_shellbags_schema(reader.fieldnames):
            raise ValueError("ShellBags 스키마 아님")

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8-sig", newline="") as f_out:
            fieldnames = ["type", "time", "description", "tag"]
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            out_count = 0
            for row in reader:
                info = tag_shellbags_row(row, now)
                desc = build_description(row)
                tag_str = "|".join(info["tags"]) if isinstance(info["tags"], list) else str(info["tags"])

                writer.writerow(
                    {
                        "type": "shellbags",
                        "time": info["timestamp"],
                        "description": desc,
                        "tag": tag_str,
                    }
                )
                out_count += 1

    return out_count


# ============================================================
# 8) 자동 탐색 + 출력 경로 구성 + 즉시 실행(main() 호출)
# ============================================================

def _find_kape_output_root(drive_root: Path) -> Optional[Path]:
    # 폴더명 혼재 대비
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
    출력: <드라이브>:\tagged\<stem>_<CASE>_tagged.csv (CASE 없으면 <stem>_tagged.csv)
    """
    drive = csv_path.drive or "D:"
    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stem = csv_path.stem
    out_name = f"{stem}_{case_name}_tagged.csv" if case_name else f"{stem}_tagged.csv"
    return _ensure_unique_output_path(tagged_dir / out_name)


def _find_candidate_csvs() -> List[Path]:
    """
    1) D:~Z: 각 드라이브의 Kape Output 아래에서
       - 먼저 *TARGET_SUFFIX 로 후보 수집
    2) 1)에서 아무것도 못 찾으면,
       - Kape Output 아래의 모든 *.csv 를 스키마로 필터링(느리지만 “인자 없이” 돌리기 위해)
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
                if is_shellbags_schema(header):
                    schema_hits.append(p)
        except Exception:
            continue

    return schema_hits


def main() -> None:
    print("[AUTO] 인자 없이 실행: D:~Z: 에서 Kape Output 아래 대상 CSV 자동 탐색")
    if TARGET_SUFFIX:
        print(f"[AUTO] 1차 필터: *{TARGET_SUFFIX}")
    else:
        print("[AUTO] 1차 필터 없음: 스키마 기반으로만 탐색")

    candidates = _find_candidate_csvs()
    if not candidates:
        print("[END] 대상 CSV 없음")
        return

    print(f"[AUTO] 대상 CSV {len(candidates)}개 발견")

    # “인자 없이” 실행이므로 now는 현재시각으로 고정
    now = datetime.now()

    for csv_path in candidates:
        case_name = _get_case_name(csv_path)
        out_path = _get_output_path(csv_path, case_name)

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
