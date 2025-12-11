import os
import re
from datetime import datetime
import pandas as pd
from pathlib import Path


# =====================================
# 0. 기본 설정
# =====================================

# 찾을 파일 이름 패턴
TARGET_SUFFIX = "_RBCmd_Output.csv"

# 굳이 버릴 열 (지금은 없음, SourceName은 태깅에 쓰고 description에서만 제외)
COLUMNS_TO_DROP = [
    # 예: "SomeColumn"
]


# =====================================
# 1. CSV 파일 찾기 (D: ~ Z:) - Kape Output 기준
# =====================================

def find_rbcmd_csv():
    """
    D:~Z: 각 드라이브에서 루트의 'Kape Output' 폴더를 찾고,
    그 아래를 재귀적으로 돌면서 *_RBCmd_Output.csv 를 찾는다.
    일단 첫 번째로 발견된 파일만 반환.
    """
    matches = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = f"{chr(drive_code)}:\\"
        if not os.path.exists(drive_root):
            continue

        kape_root = os.path.join(drive_root, "Kape Output")
        if not os.path.isdir(kape_root):
            continue

        print(f"[DEBUG] 드라이브 {drive_root} 의 Kape Output 탐색: {kape_root}")

        for root, dirs, files in os.walk(kape_root):
            for fname in files:
                if fname.endswith(TARGET_SUFFIX):
                    full_path = os.path.join(root, fname)
                    print(f"[DEBUG] RBCmd 후보 발견: {full_path}")
                    matches.append(full_path)

    if not matches:
        return None

    # 일단 첫 번째 것만 사용 (기존 로직 유지)
    return matches[0]


# =====================================
# 2. 파일명에서 캡처 시각 추출
#    예: 20251102074048_RBCmd_Output.csv
# =====================================

def extract_capture_dt_from_filename(path):
    basename = os.path.basename(path)
    m = re.match(r"^(\d{14})_", basename)
    if not m:
        return None
    dt_str = m.group(1)  # "YYYYMMDDHHMMSS"
    return datetime.strptime(dt_str, "%Y%m%d%H%M%S")


# =====================================
# 2-1. Kape Output 하위 CASE 폴더 이름 추출
#       (Kape Output 바로 아래 1단계 폴더명만)
# =====================================

def get_kape_child_folder_name(csv_path: str):
    """
    csv_path 가
        <드라이브>:\Kape Output\<CASE>\...\file.csv
    형태라고 가정하고,

    - 'Kape Output' 폴더를 위로 올라가며 찾은 뒤
    - 그 기준 상대 경로의 첫 번째 부분(하위 폴더 이름, 예: 'Jo', 'Terry') 하나만 반환.

    못 찾으면 None.
    """
    p = Path(csv_path)
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None

            # 예: rel.parts = ('Jo', 'RBCmd', '...', 'file.csv')
            if rel.parts:
                return rel.parts[0]
            return None

    return None


# =====================================
# 3. 확장자 -> FORMAT_ 매핑
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
# 4. 이름 기반 의심(SUS_NAME) 헬퍼
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
# 5. 경로 정규화 (\\?\C:\... 제거)
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
# 6. TIME_* 태그
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
# 7. 한 행(row)에 대한 태그 생성
#    - 확장자/SEC_* 판단은 FileName 기준
# =====================================

def generate_tags_for_row(row, capture_dt):
    tags = set()

    # 7-1) 기본 아티팩트
    tags.add("ARTIFACT_RECYCLE_BIN")
    tags.add("STATE_DELETED")
    tags.add("ACT_FILE_OPERATION")
    tags.add("EVENT_DELETE")

    # 7-2) 원래 파일 경로 (FileName 기준)
    file_name_raw = row.get("FileName")
    if pd.isna(file_name_raw):
        file_name_raw = ""
    path = normalize_fs_path(str(file_name_raw))
    path_lower = path.lower()
    basename = os.path.basename(path)
    ext = os.path.splitext(basename)[1].lower()

    # FORMAT_ (FileName 확장자 기준)
    if ext:
        fmt_tag = extension_to_format_tag(ext)
        if fmt_tag:
            tags.add(fmt_tag)

    # 실행/스크립트 여부 (FileName 기준)
    is_exec = ext in [".exe", ".dll", ".sys", ".scr", ".com"]
    is_script = ext in [".ps1", ".bat", ".cmd", ".vbs", ".js"]

    if is_exec:
        tags.add("SEC_EXECUTABLE")
    if is_script:
        tags.add("SEC_SCRIPT")

    # AREA_ (원래 위치 기준)
    if "\\users\\" in path_lower and "\\desktop\\" in path_lower:
        tags.add("AREA_USER_DESKTOP")
    if "\\users\\" in path_lower and "\\downloads\\" in path_lower:
        tags.add("AREA_USER_DOWNLOADS")
    if "\\users\\" in path_lower and "\\appdata\\local\\" in path_lower:
        tags.add("AREA_APPDATA_LOCAL")
    if "\\appdata\\roaming\\" in path_lower:
        tags.add("AREA_APPDATA_ROAMING")
    if "\\appdata\\locallow\\" in path_lower:
        tags.add("AREA_APPDATA_LOCALLOW")

    if "\\program files" in path_lower:
        tags.add("AREA_PROGRAMFILES")
    if "\\programdata\\" in path_lower or path_lower.startswith("c:\\programdata"):
        tags.add("AREA_PROGRAMDATA")

    if "\\temp\\" in path_lower or "\\systemtemp\\" in path_lower:
        tags.add("AREA_TEMP")

    # D:~Z: 드라이브 → 외장/별도 드라이브
    if re.match(r"^[d-z]:\\\\", path_lower):
        tags.add("AREA_EXTERNAL_DRIVE")

    # 휴지통 경로 태그 (SourceName 기준으로 AREA_RECYCLE_BIN)
    src = str(row.get("SourceName", "") or "").lower()
    if "\\$recycle.bin\\" in src:
        tags.add("AREA_RECYCLE_BIN")

    # SEC_SUSPICIOUS_NAME (파일 이름 기준, 실행/스크립트일 때만)
    is_exec_or_script = is_exec or is_script
    if is_exec_or_script and basename:
        if is_suspicious_name(basename, ext):
            tags.add("SEC_SUSPICIOUS_NAME")

    # TIME_* (DeletedOn → lastwritetimestemp 기준)
    event_dt = row.get("lastwritetimestemp")
    time_tags = get_time_bucket_tags(capture_dt, event_dt, base_tag="TIME_MODIFIED")
    tags.update(time_tags)

    return sorted(tags)


# =====================================
# 8. descrition 생성
#    - "키: 값 | 키: 값 | ..." 형태
#    - type, tag, lastwritetimestemp, DeletedOn, SourceName 제외
# =====================================

def make_description(row):
    data = row.to_dict()

    data.pop("type", None)
    data.pop("tag", None)
    data.pop("lastwritetimestemp", None)
    data.pop("DeletedOn", None)
    data.pop("SourceName", None)

    parts = []
    for key, val in data.items():
        # NaN / NaT 처리
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
# 9. 출력 경로: 드라이브\tagged\*.csv
#    + 파일명에 CASE 이름 포함
# =====================================

def get_tagged_output_path(csv_path: str, case_name: str | None) -> str:
    """
    - 드라이브 루트에 'tagged' 폴더 생성 (ccit 와 같은 레벨)
      예) D:\tagged
    - 파일명은 원본 stem + CASE 이름 + _normalized.csv
      예) 20251102074048_RBCmd_Output_Jo_normalized.csv
    """
    drive, _ = os.path.splitdrive(csv_path)
    if not drive:
        # 드라이브 정보를 못 얻으면 원래 폴더 기준
        base_dir = os.path.dirname(csv_path)
    else:
        base_dir = drive + "\\"

    tagged_dir = os.path.join(base_dir, "tagged")
    os.makedirs(tagged_dir, exist_ok=True)

    base_name = os.path.basename(csv_path)
    stem, ext = os.path.splitext(base_name)

    if case_name:
        out_name = f"{stem}_{case_name}_normalized.csv"
    else:
        out_name = f"{stem}_normalized.csv"

    return os.path.join(tagged_dir, out_name)


# =====================================
# 10. 메인 정규화 함수
# =====================================

def normalize_rbcmd_csv(csv_path):
    print(f"[+] Target CSV: {csv_path}")
    capture_dt = extract_capture_dt_from_filename(csv_path)
    print(f"[+] Capture datetime from filename: {capture_dt}")

    case_name = get_kape_child_folder_name(csv_path)
    if case_name:
        print(f"[+] Kape Output 하위 CASE 폴더: {case_name}")
    else:
        print("[!] Kape Output 하위 CASE 폴더를 찾지 못함 (파일명에 CASE 미반영)")

    # CSV 로드
    df = pd.read_csv(csv_path, encoding="utf-8-sig")

    # 불필요한 열 제거
    drop_cols = [c for c in COLUMNS_TO_DROP if c in df.columns]
    if drop_cols:
        print(f"[+] Dropping columns: {drop_cols}")
        df = df.drop(columns=drop_cols)

    # 시간 컬럼: DeletedOn → lastwritetimestemp
    if "DeletedOn" in df.columns:
        df["lastwritetimestemp"] = pd.to_datetime(df["DeletedOn"], errors="coerce")
        print("[+] Using time column: DeletedOn -> lastwritetimestemp")
    else:
        df["lastwritetimestemp"] = pd.NaT
        print("[!] DeletedOn column not found. lastwritetimestemp set to NaT.")

    # 태그 생성
    tags_list = []
    for _, row in df.iterrows():
        tags = generate_tags_for_row(row, capture_dt)
        tags_list.append("|".join(tags))

    df["tag"] = tags_list
    df["type"] = "RECYCLE_BIN"
    df["descrition"] = df.apply(make_description, axis=1)

    # 최종 컬럼만 남기기
    out_df = df[["type", "lastwritetimestemp", "descrition", "tag"]]

    # 저장 위치: 드라이브\tagged\*.csv (CASE 이름 포함)
    out_path = get_tagged_output_path(csv_path, case_name)
    out_df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"[+] Normalized CSV saved to: {out_path}")


# =====================================
# 11. 엔트리 포인트
# =====================================

if __name__ == "__main__":
    csv_path = find_rbcmd_csv()
    if not csv_path:
        print("[!] Target RBCmd CSV not found. Check drives/paths.")
    else:
        normalize_rbcmd_csv(csv_path)
