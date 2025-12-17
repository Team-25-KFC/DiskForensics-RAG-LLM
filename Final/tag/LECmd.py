# -*- coding: utf-8 -*-
import os
import re
import json
from datetime import datetime
from typing import List, Optional, Tuple
from pathlib import Path

import pandas as pd


# =====================================
# 0. 기본 설정
# =====================================

TARGET_SUFFIX = "_LECmd_Output.csv"

# 필요 없다고 판단한 열
COLUMNS_TO_DROP = [
    "SourceFile",  # E:\Kape Output\... 경로 → 증거 식별은 상위 메타에서 관리
]


# =====================================
# 1. CSV 파일 찾기 (D: ~ Z:, Kape Output 아래)
# =====================================

def find_lecmd_csvs_under_kape_output() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 전체를 돌면서
      <드라이브>:\Kape Output\...\*_LECmd_Output.csv
    패턴을 모두 찾고,
    (csv_path, 파일명 기준 캡처시각) 리스트를 반환.
    """
    results: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = drive_root / "Kape Output"
        if not kape_root.exists():
            continue

        print(f"[DEBUG] 드라이브 {drive_root} 의 Kape Output 탐색: {kape_root}")

        for root, dirs, files in os.walk(str(kape_root)):
            for fname in files:
                if not fname.endswith(TARGET_SUFFIX):
                    continue

                full_path = Path(root) / fname
                capture_dt = extract_capture_dt_from_filename(fname)
                if capture_dt is None:
                    print(f"[DEBUG] LECmd 후보 파일이지만 날짜 파싱 실패: {fname}")
                else:
                    print(f"[DEBUG] LECmd 후보 파일: {fname}, capture_dt={capture_dt}")

                results.append((full_path, capture_dt))

    if not results:
        print("[DEBUG] LECmd 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] LECmd 후보 파일 개수: {len(results)}")

    return results


# =====================================
# 1-1. 파일명에서 캡처 시각 추출
#      예: 20251126183950_LECmd_Output.csv
# =====================================

def extract_capture_dt_from_filename(name_or_path) -> Optional[datetime]:
    basename = os.path.basename(str(name_or_path))
    m = re.match(r"^(\d{14})_", basename)
    if not m:
        return None
    dt_str = m.group(1)  # "YYYYMMDDHHMMSS"
    try:
        return datetime.strptime(dt_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# =====================================
# 1-2. Kape Output 하위 1단계 폴더명 추출
#      예: D:\Kape Output\Jo\SQLECmd\...\file.csv → "Jo"
# =====================================

def get_kape_child_folder_name(csv_path: Path) -> Optional[str]:
    """
    csv_path 가
        <드라이브>:\Kape Output\<CASE>\...\file.csv
    형태라고 가정하고,
    'Kape Output' 기준 상대 경로의 첫 부분(<CASE>)을 반환.
    """
    p = csv_path
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None

            if rel.parts:
                return rel.parts[0]
            return None

    return None


# =====================================
# 2. 확장자 -> FORMAT_ 매핑
# =====================================

EXT_TO_FORMAT = {
    # 문서
    ".doc": "FORMAT_DOCUMENT",
    ".docx": "FORMAT_DOCUMENT",
    ".pdf": "FORMAT_DOCUMENT",
    ".txt": "FORMAT_DOCUMENT",
    ".rtf": "FORMAT_DOCUMENT",
    ".odt": "FORMAT_DOCUMENT",

    # 스프레드시트
    ".xls": "FORMAT_SPREADSHEET",
    ".xlsx": "FORMAT_SPREADSHEET",
    ".csv": "FORMAT_SPREADSHEET",

    # 프레젠테이션
    ".ppt": "FORMAT_PRESENTATION",
    ".pptx": "FORMAT_PRESENTATION",

    # 이미지
    ".jpg": "FORMAT_IMAGE",
    ".jpeg": "FORMAT_IMAGE",
    ".png": "FORMAT_IMAGE",
    ".gif": "FORMAT_IMAGE",
    ".bmp": "FORMAT_IMAGE",
    ".ico": "FORMAT_IMAGE",
    ".svg": "FORMAT_IMAGE",

    # 오디오
    ".mp3": "FORMAT_AUDIO",
    ".wav": "FORMAT_AUDIO",
    ".flac": "FORMAT_AUDIO",
    ".wma": "FORMAT_AUDIO",

    # 비디오
    ".mp4": "FORMAT_VIDEO",
    ".avi": "FORMAT_VIDEO",
    ".mkv": "FORMAT_VIDEO",
    ".mov": "FORMAT_VIDEO",
    ".wmv": "FORMAT_VIDEO",

    # 실행/스크립트
    ".exe": "FORMAT_EXECUTABLE",
    ".dll": "FORMAT_EXECUTABLE",
    ".sys": "FORMAT_EXECUTABLE",
    ".scr": "FORMAT_EXECUTABLE",
    ".com": "FORMAT_EXECUTABLE",

    ".ps1": "FORMAT_SCRIPT",
    ".bat": "FORMAT_SCRIPT",
    ".cmd": "FORMAT_SCRIPT",
    ".vbs": "FORMAT_SCRIPT",
    ".js": "FORMAT_SCRIPT",
    ".py": "FORMAT_SCRIPT",

    # 아카이브
    ".zip": "FORMAT_ARCHIVE",
    ".rar": "FORMAT_ARCHIVE",
    ".7z": "FORMAT_ARCHIVE",
    ".tar": "FORMAT_ARCHIVE",
    ".gz": "FORMAT_ARCHIVE",
}


def extension_to_format_tag(ext: str):
    return EXT_TO_FORMAT.get(ext.lower())


# =====================================
# 3. 이름 기반 의심(SUS_NAME) 헬퍼
# =====================================

SUSPICIOUS_KEYWORDS = [
    "crack", "keygen", "payload", "mimikatz", "hack", "exploit"
]


def looks_like_hash(name_no_ext: str) -> bool:
    # 16진수 해시처럼 보이면 True
    if len(name_no_ext) < 32:
        return False
    if len(name_no_ext) > 80:
        return False
    return all(c in "0123456789abcdef" for c in name_no_ext.lower())


def is_double_extension_exe(basename: str) -> bool:
    # foo.pdf.exe 같은 형태
    return bool(
        re.search(
            r"\.(doc|docx|pdf|jpg|jpeg|png|xls|xlsx|ppt|pptx|txt)\.exe$",
            basename.lower()
        )
    )


def has_non_ascii(s: str) -> bool:
    return any(ord(ch) > 127 for ch in s)


def is_suspicious_name(basename: str, ext: str) -> bool:
    name_no_ext, _ = os.path.splitext(basename)
    lower = basename.lower()

    # 1) 키워드 포함
    if any(kw in lower for kw in SUSPICIOUS_KEYWORDS):
        return True

    # 2) 더블 확장자 위장
    if is_double_extension_exe(basename):
        return True

    # 3) 해시 형태 이름
    if looks_like_hash(name_no_ext):
        return True

    # 4) 비 ASCII + 실행계열
    if has_non_ascii(name_no_ext) and ext.lower() in [".exe", ".dll", ".sys", ".scr", ".com"]:
        return True

    return False


# =====================================
# 4. 경로 정규화 (\\?\C:\... 제거)
# =====================================

def normalize_fs_path(path: str) -> str:
    if path is None:
        return ""
    p = str(path).strip()
    # \\?\C:\... 프리픽스 제거
    if p.lower().startswith('\\\\?\\'):
        p = p[4:]
    return p


# =====================================
# 5. TIME_* 태그
# =====================================

def get_time_bucket_tags(capture_dt, event_dt, base_tag=None):
    tags = []
    if base_tag:
        tags.append(base_tag)
    if capture_dt is None or event_dt is None:
        return tags

    # pandas Timestamp → datetime 변환
    if isinstance(event_dt, pd.Timestamp):
        if pd.isna(event_dt):
            return tags
        event_dt = event_dt.to_pydatetime()

    delta = capture_dt - event_dt
    days = delta.total_seconds() / 86400.0

    if days <= 1:
        tags.append("TIME_RECENT")
    elif days <= 7:
        tags.append("TIME_WEEK")
    elif days <= 30:
        tags.append("TIME_MONTH")
    else:
        tags.append("TIME_OLD")

    return tags


# =====================================
# 6. 한 행(row)에 대한 태그 생성
#    - 확장자/SEC_* 판단은 LocalPath 기준
# =====================================

def generate_tags_for_row(row, capture_dt):
    tags = set()

    # LNK 아티팩트 고정
    tags.add("ARTIFACT_LNK")
    tags.add("FORMAT_SHORTCUT")

    # 6-1) 타겟 경로: LocalPath만 사용
    target_path_raw = row.get("LocalPath")
    if pd.isna(target_path_raw):
        target_path_raw = ""
    target_path = normalize_fs_path(str(target_path_raw))
    target_lower = target_path.lower()
    basename = os.path.basename(target_path)
    ext = os.path.splitext(basename)[1].lower()

    # FORMAT_ (타겟 기준, LocalPath만)
    if ext:
        fmt_tag = extension_to_format_tag(ext)
        if fmt_tag:
            tags.add(fmt_tag)

    # 실행/스크립트 여부 (LocalPath 기준)
    is_exec = ext in [".exe", ".dll", ".sys", ".scr", ".com"]
    is_script = ext in [".ps1", ".bat", ".cmd", ".vbs", ".js"]

    # ACT_ / EVENT_
    if is_exec:
        tags.add("ACT_EXECUTE")
        tags.add("EVENT_EXECUTED")
        tags.add("EVENT_ACCESSED")
    else:
        # 문서/이미지 등
        tags.add("ACT_FILE_OPERATION")
        tags.add("EVENT_ACCESSED")

    # SEC_EXECUTABLE / SEC_SCRIPT
    if is_exec:
        tags.add("SEC_EXECUTABLE")
    if is_script:
        tags.add("SEC_SCRIPT")

    # AREA_ (타겟 위치 기준)
    if target_lower.startswith("c:\\windows\\system32") or target_lower.startswith("c:\\windows\\syswow64"):
        tags.add("AREA_SYSTEM32")
        tags.add("AREA_WINDOWS")
    elif target_lower.startswith("c:\\windows"):
        tags.add("AREA_WINDOWS")

    if "\\users\\" in target_lower and "\\desktop\\" in target_lower:
        tags.add("AREA_USER_DESKTOP")
    if "\\users\\" in target_lower and "\\downloads\\" in target_lower:
        tags.add("AREA_USER_DOWNLOADS")
    if "\\users\\" in target_lower and "\\appdata\\local\\" in target_lower:
        tags.add("AREA_APPDATA_LOCAL")
    if "\\appdata\\roaming\\" in target_lower:
        tags.add("AREA_APPDATA_ROAMING")
    if "\\appdata\\locallow\\" in target_lower:
        tags.add("AREA_APPDATA_LOCALLOW")

    if "\\program files" in target_lower:
        tags.add("AREA_PROGRAMFILES")
    if "\\programdata\\" in target_lower or target_lower.startswith("c:\\programdata"):
        tags.add("AREA_PROGRAMDATA")

    if "\\temp\\" in target_lower or "\\systemtemp\\" in target_lower:
        tags.add("AREA_TEMP")

    # D:~Z: 드라이브 → 외장/별도 드라이브로 취급
    if re.match(r"^[d-z]:\\\\", target_lower):
        tags.add("AREA_EXTERNAL_DRIVE")

    # UNC 네트워크 경로
    if target_lower.startswith("\\\\") and not target_lower.startswith("\\\\?\\c:"):
        tags.add("AREA_NETWORK_SHARE")

    # SEC_SUSPICIOUS_NAME (타겟 파일 이름 기준, 실행/스크립트일 때만)
    is_exec_or_script = is_exec or is_script
    if is_exec_or_script and basename:
        if is_suspicious_name(basename, ext):
            tags.add("SEC_SUSPICIOUS_NAME")

    # TIME_* (SourceAccessed → lastwritetimestemp 기준)
    event_dt = row.get("lastwritetimestemp")
    time_tags = get_time_bucket_tags(capture_dt, event_dt, base_tag="TIME_ACCESSED")
    tags.update(time_tags)

    return sorted(tags)


# =====================================
# 7. descrition 생성
#    - "키: 값 | 키: 값 | ..." 형태로
#    - type, tag, lastwritetimestemp, SourceAccessed, SourceFile 제외
# =====================================

def make_description(row):
    data = row.to_dict()

    # 메타/중복 정보 제거
    data.pop("type", None)
    data.pop("tag", None)
    data.pop("lastwritetimestemp", None)
    data.pop("SourceAccessed", None)
    data.pop("SourceFile", None)

    parts = []
    for key, val in data.items():
        if isinstance(val, pd.Timestamp):
            if pd.isna(val):
                continue
            val_str = str(val)
        else:
            try:
                if pd.isna(val):
                    continue
            except Exception:
                pass
            val_str = str(val)
        parts.append(f"{key}: {val_str}")

    return " | ".join(parts)


# =====================================
# 8. output 파일명 충돌 처리 (_v1, _v2 ...)
# =====================================

def ensure_unique_output_path(path: Path) -> Path:
    """
    이미 같은 이름의 파일이 있으면
    *_normalized_v1.csv, *_normalized_v2.csv ... 식으로
    사용 가능한 새 경로를 돌려준다.
    """
    if not path.exists():
        return path

    base, ext = os.path.splitext(str(path))
    idx = 1
    while True:
        candidate = Path(f"{base}_v{idx}{ext}")
        if not candidate.exists():
            return candidate
        idx += 1


# =====================================
# 9. 출력 경로: 드라이브 루트\tagged\*.csv
# =====================================

def get_tagged_output_path(csv_path: Path, case_name: Optional[str]) -> Path:
    """
    - 출력 디렉터리: <드라이브>:\tagged
    - 파일명: <원래스텀>_<CASE>_normalized.csv (CASE 없으면 그냥 _normalized)
    """
    drive = csv_path.drive or "D:"
    tagged_dir = Path(drive + "\\tagged")
    tagged_dir.mkdir(parents=True, exist_ok=True)

    base_name = csv_path.name
    stem, ext = os.path.splitext(base_name)

    if case_name:
        out_name = f"{stem}_{case_name}_normalized.csv"
    else:
        out_name = f"{stem}_normalized.csv"

    out_path = tagged_dir / out_name
    return ensure_unique_output_path(out_path)


# =====================================
# 10. 메인 정규화 함수 (단일 CSV)
# =====================================

def normalize_lecmd_csv(csv_path: Path,
                        capture_dt: Optional[datetime],
                        case_name: Optional[str]):
    print(f"[+] Target CSV: {csv_path}")
    if capture_dt is None:
        capture_dt = extract_capture_dt_from_filename(csv_path)

    print(f"[+] Capture datetime from filename: {capture_dt}")

    # CSV 로드
    df = pd.read_csv(csv_path, encoding="utf-8-sig")

    # 불필요한 열 제거
    drop_cols = [c for c in COLUMNS_TO_DROP if c in df.columns]
    if drop_cols:
        print(f"[+] Dropping columns: {drop_cols}")
        df = df.drop(columns=drop_cols)

    # 시간 컬럼: SourceAccessed → lastwritetimestemp
    if "SourceAccessed" in df.columns:
        df["lastwritetimestemp"] = pd.to_datetime(df["SourceAccessed"], errors="coerce")
        print("[+] Using time column: SourceAccessed -> lastwritetimestemp")
    else:
        df["lastwritetimestemp"] = pd.NaT
        print("[!] SourceAccessed column not found. lastwritetimestemp set to NaT.")

    # 태그 생성
    tags_list = []
    for _, row in df.iterrows():
        tags = generate_tags_for_row(row, capture_dt)
        tags_list.append("|".join(tags))

    df["tag"] = tags_list
    df["type"] = "LNK"
    df["descrition"] = df.apply(make_description, axis=1)

    # 최종 컬럼만 남기기
    out_df = df[["type", "lastwritetimestemp", "descrition", "tag"]]

    # 저장 위치: <드라이브>:\tagged\*.csv
    out_path = get_tagged_output_path(csv_path, case_name)
    out_df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"[+] Normalized CSV saved to: {out_path}")


# =====================================
# 11. 엔트리 포인트
# =====================================

def main():
    print("[LECmd] D:~Z: + 'Kape Output' 경로에서 *_LECmd_Output.csv 탐색 중...")

    candidates = find_lecmd_csvs_under_kape_output()
    if not candidates:
        print("[!] Target LECmd CSV not found. Check drives/paths and 'Kape Output' folder.")
        return

    for csv_path, capture_dt in candidates:
        case_name = get_kape_child_folder_name(csv_path)
        if case_name:
            print(f"[+] CASE 폴더: {case_name}")
        else:
            print("[!] CASE 폴더명(Kape Output 하위 1단계)을 찾지 못함")

        normalize_lecmd_csv(csv_path, capture_dt, case_name)


if __name__ == "__main__":
    main()
