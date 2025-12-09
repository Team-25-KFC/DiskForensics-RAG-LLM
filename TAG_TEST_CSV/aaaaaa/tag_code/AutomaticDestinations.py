import os
import re
from datetime import datetime
import pandas as pd


# =====================================
# 0. 기본 설정
# =====================================

TARGET_SUFFIX = "_AutomaticDestinations.csv"

# 필요 시 드랍할 컬럼 (지금은 사용 X)
COLUMNS_TO_DROP = [
    # 예: "SomeColumn"
]


# =====================================
# 1. CSV 파일 찾기 (D: ~ Z:, ccit 아래)
# =====================================

def find_auto_dest_csv():
    matches = []
    for drive_code in range(ord("D"), ord("Z") + 1):
        drive = f"{chr(drive_code)}:\\"
        if not os.path.exists(drive):
            continue

        for root, dirs, files in os.walk(drive):
            lower_root = root.lower()
            if "ccit" not in lower_root:
                continue

            for fname in files:
                if fname.endswith(TARGET_SUFFIX):
                    matches.append(os.path.join(root, fname))

    if not matches:
        return None
    # 여러 개면 일단 첫 번째
    return matches[0]


# =====================================
# 2. 파일명에서 캡처 시각 추출
#    예: 20251102074043_AutomaticDestinations.csv
# =====================================

def extract_capture_dt_from_filename(path: str):
    basename = os.path.basename(path)
    m = re.match(r"^(\d{14})_", basename)
    if not m:
        return None
    dt_str = m.group(1)
    return datetime.strptime(dt_str, "%Y%m%d%H%M%S")


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
# 4. 의심스러운 이름(SUS_NAME) 헬퍼
# =====================================

SUSPICIOUS_KEYWORDS = [
    "crack", "keygen", "payload", "mimikatz", "hack", "exploit"
]


def looks_like_hash(name_no_ext: str) -> bool:
    if len(name_no_ext) < 32 or len(name_no_ext) > 80:
        return False
    return all(c in "0123456789abcdef" for c in name_no_ext.lower())


def is_double_extension_exe(basename: str) -> bool:
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

    # 1) 키워드
    if any(kw in lower for kw in SUSPICIOUS_KEYWORDS):
        return True

    # 2) 이중 확장자
    if is_double_extension_exe(basename):
        return True

    # 3) 해시처럼 보이는 이름
    if looks_like_hash(name_no_ext):
        return True

    # 4) 비ASCII + 실행계열
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
# 6. 한글 모지바케(½ºÅ©¸°¼¦ 등) 복구 시도
# =====================================

def fix_korean_mojibake(s: str) -> str:
    """
    ½ºÅ©¸°¼¦ 같은 한글 모지바케를
    latin1 → cp949 재디코딩으로 복구 시도.
    실패하면 원본 반환.
    """
    if not isinstance(s, str):
        return s

    # 이미 정상 한글이 포함되어 있으면 건드리지 않음
    if re.search(r'[\u3130-\u318F\uAC00-\uD7A3]', s):
        return s

    # 라틴1 범위 문자(모지바케에서 자주 나오는 범위)가 없으면 패스
    if not any('\u00a0' <= ch <= '\u00ff' for ch in s):
        return s

    try:
        return s.encode("latin1").decode("cp949")
    except Exception:
        return s


# =====================================
# 7. TIME_* 태그
# =====================================

def get_time_bucket_tags(capture_dt, event_dt, base_tag=None):
    tags = []
    if base_tag:
        tags.append(base_tag)
    if capture_dt is None or event_dt is None:
        return tags

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
# 8. 한 행(row) 태깅
#    - 타겟 경로: LocalPath > Path 만 사용
#    - ACT_/EVENT_: 확장자 기준으로 각각 하나만
# =====================================

def generate_tags_for_row(row, capture_dt):
    tags = set()

    # 기본 아티팩트 타입
    tags.add("ARTIFACT_JUMPLIST")

    # 타겟 경로 선정: LocalPath > Path
    target_path_raw = (
        row.get("LocalPath")
        or row.get("Path")
        or ""
    )
    target_path = normalize_fs_path(str(target_path_raw))
    lower = target_path.lower()
    basename = os.path.basename(target_path)
    ext = os.path.splitext(basename)[1].lower()

    # FORMAT_ (타겟 기준)
    if ext:
        fmt_tag = extension_to_format_tag(ext)
        if fmt_tag:
            tags.add(fmt_tag)

    # 실행/스크립트 여부
    is_exec = ext in [".exe", ".dll", ".sys", ".scr", ".com"]
    is_script = ext in [".ps1", ".bat", ".cmd", ".vbs", ".js"]

    # ACT_ / EVENT_ : 확장자 기반으로 각각 하나만
    if is_exec or is_script:
        tags.add("ACT_EXECUTE")
        tags.add("EVENT_EXECUTED")
    else:
        tags.add("ACT_FILE_OPERATION")
        tags.add("EVENT_ACCESSED")

    # SEC_EXECUTABLE / SEC_SCRIPT
    if is_exec:
        tags.add("SEC_EXECUTABLE")
    if is_script:
        tags.add("SEC_SCRIPT")

    # AREA_
    if lower.startswith("c:\\windows\\system32") or lower.startswith("c:\\windows\\syswow64"):
        tags.add("AREA_SYSTEM32")
        tags.add("AREA_WINDOWS")
    elif lower.startswith("c:\\windows"):
        tags.add("AREA_WINDOWS")

    if "\\users\\" in lower and "\\desktop\\" in lower:
        tags.add("AREA_USER_DESKTOP")
    if "\\users\\" in lower and "\\downloads\\" in lower:
        tags.add("AREA_USER_DOWNLOADS")
    if "\\users\\" in lower and "\\appdata\\local\\" in lower:
        tags.add("AREA_APPDATA_LOCAL")
    if "\\appdata\\roaming\\" in lower:
        tags.add("AREA_APPDATA_ROAMING")
    if "\\appdata\\locallow\\" in lower:
        tags.add("AREA_APPDATA_LOCALLOW")

    if "\\program files" in lower:
        tags.add("AREA_PROGRAMFILES")
    if "\\programdata\\" in lower or lower.startswith("c:\\programdata"):
        tags.add("AREA_PROGRAMDATA")

    if "\\temp\\" in lower or "\\systemtemp\\" in lower:
        tags.add("AREA_TEMP")

    if re.match(r"^[d-z]:\\\\", lower):
        tags.add("AREA_EXTERNAL_DRIVE")

    if lower.startswith("\\\\") and not lower.startswith("\\\\?\\c:"):
        tags.add("AREA_NETWORK_SHARE")

    # SEC_SUSPICIOUS_PATH 는 사용하지 않음 (경로만으로 판단 X)

    # SEC_SUSPICIOUS_NAME (실행/스크립트 + 이름 기준)
    if (is_exec or is_script) and basename:
        if is_suspicious_name(basename, ext):
            tags.add("SEC_SUSPICIOUS_NAME")

    # TIME_* (LastModified → lastwritetimestemp 기준)
    event_dt = row.get("lastwritetimestemp")
    time_tags = get_time_bucket_tags(capture_dt, event_dt, base_tag="TIME_ACCESSED")
    tags.update(time_tags)

    return sorted(tags)


# =====================================
# 9. descrition 생성
#    - "키: 값 | 키: 값 | ..." 형식
#    - type, tag, lastwritetimestemp, LastModified, SourceFile 제거
# =====================================

def make_description(row):
    data = row.to_dict()

    data.pop("type", None)
    data.pop("tag", None)
    data.pop("lastwritetimestemp", None)
    data.pop("LastModified", None)
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
# 10. 저장 경로: 드라이브\ccit\tagged\*.csv
# =====================================

def get_tagged_output_path(csv_path: str) -> str:
    lower = csv_path.lower()
    marker = "\\ccit\\"
    idx = lower.find(marker)
    if idx == -1:
        base_dir = os.path.dirname(csv_path)
        tagged_dir = os.path.join(base_dir, "tagged")
    else:
        # 예: D:\ccit\Adware...\ → D:\ccit\ 까지
        ccit_dir = csv_path[: idx + len(marker)]
        tagged_dir = os.path.join(ccit_dir, "tagged")

    os.makedirs(tagged_dir, exist_ok=True)

    base_name = os.path.basename(csv_path)
    stem, ext = os.path.splitext(base_name)
    out_name = f"{stem}_normalized.csv"
    return os.path.join(tagged_dir, out_name)


# =====================================
# 11. 메인 정규화 함수
# =====================================

def normalize_auto_dest_csv(csv_path: str):
    print(f"[+] Target CSV: {csv_path}")
    capture_dt = extract_capture_dt_from_filename(csv_path)
    print(f"[+] Capture datetime from filename: {capture_dt}")

    df = pd.read_csv(csv_path, encoding="utf-8-sig")

    # 모지바케 복구: LocalPath, Path 컬럼에 대해 시도
    for col in ["LocalPath", "Path"]:
        if col in df.columns:
            df[col] = df[col].astype(str).apply(fix_korean_mojibake)

    # 필요시 컬럼 드랍
    drop_cols = [c for c in COLUMNS_TO_DROP if c in df.columns]
    if drop_cols:
        print(f"[+] Dropping columns: {drop_cols}")
        df = df.drop(columns=drop_cols)

    # LastModified → lastwritetimestemp
    if "LastModified" in df.columns:
        df["lastwritetimestemp"] = pd.to_datetime(df["LastModified"], errors="coerce")
        print("[+] Using time column: LastModified -> lastwritetimestemp")
    else:
        df["lastwritetimestemp"] = pd.NaT
        print("[!] LastModified column not found. lastwritetimestemp set to NaT.")

    # 태그 생성
    tags_list = []
    for _, row in df.iterrows():
        tags = generate_tags_for_row(row, capture_dt)
        tags_list.append("|".join(tags))

    df["tag"] = tags_list
    df["type"] = "JUMPLIST(AUTOMATIC)"
    df["descrition"] = df.apply(make_description, axis=1)

    # 최종 컬럼 정리
    out_df = df[["type", "lastwritetimestemp", "descrition", "tag"]]

    out_path = get_tagged_output_path(csv_path)
    out_df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"[+] Normalized CSV saved to: {out_path}")


# =====================================
# 12. 엔트리 포인트
# =====================================

if __name__ == "__main__":
    csv_path = find_auto_dest_csv()
    if not csv_path:
        print("[!] Target AutomaticDestinations CSV not found. Check drives/paths and ccit folder.")
    else:
        normalize_auto_dest_csv(csv_path)
