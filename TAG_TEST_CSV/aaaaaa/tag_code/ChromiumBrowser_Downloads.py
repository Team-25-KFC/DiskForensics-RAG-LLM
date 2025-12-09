# -*- coding: utf-8 -*-
import os
import re
import csv
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path

# ===============================
# 0. 유틸: 파일명에서 기준 시각(ref_time) 추출
# ===============================

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    예:
        20251114143911539097_ChromiumBrowser_Downloads_xxx.csv
        20251114143954_PECmd_Output.csv
    처럼 앞에 14자리(YYYYMMDDHHMMSS) + (옵션) 6자리 마이크로초가 붙어 있을 수 있음.

    → 우리는 앞 14자리만 기준 시간으로 사용.
    """
    base = os.path.basename(filename)

    if len(base) < 14:
        return None

    ts_str = base[:14]  # 20251114143911

    if not ts_str.isdigit():
        return None

    try:
        return datetime.strptime(ts_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ===============================
# 1. D:~Z: 전체에서 ccit 아래 Downloads CSV 찾기
# ===============================

def find_all_download_csv_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 전체를 돌면서:
      - root 경로에 'ccit'가 포함된 경우만 탐색 유지
      - 그 아래에서 '*_ChromiumBrowser_Downloads_*.csv' 파일들을 찾음
      - 파일명 앞 14자리(YYYYMMDDHHMMSS)를 ref_time으로 파싱

    반환:
      [(파일 Path, ref_time or None), ...]
    """
    candidate_files: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        for root, dirs, files in os.walk(str(drive_root)):
            lower_root = root.lower()
            if "ccit" not in lower_root:
                continue

            for name in files:
                if "_ChromiumBrowser_Downloads_" not in name:
                    continue

                full_path = Path(root) / name
                ref_time = parse_ref_time_from_filename(name)
                if ref_time is None:
                    print(f"[DEBUG] 날짜 파싱 실패: {name}")
                candidate_files.append((full_path, ref_time))

    return candidate_files


# ===============================
# 2. 날짜/시간 파서 & TIME 버킷 계산
# ===============================

def parse_dt_generic(s: str) -> Optional[datetime]:
    """
    Downloads CSV의 StartTime / LastAccessTime 같은 문자열을 datetime으로 변환.
    - 빈 값 또는 '1601-01-01 00:00:00' 은 None 취급.
    """
    if not s:
        return None
    s = s.strip()
    if not s:
        return None

    # 크롬 기본 더미 시간 (유효 X)
    if s.startswith("1601-01-01"):
        return None

    # 자주 나오는 포맷들 시도
    for fmt in ("%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    # 마지막 시도
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def get_time_tags_for_download(
    base_dt: Optional[datetime],
    use_access: bool,
    ref_time: Optional[datetime]
) -> List[str]:
    """
    - base_dt: LastAccessTime 또는 StartTime 중 최종적으로 기준으로 삼을 시간
    - use_access: base_dt가 LastAccessTime인지 여부
    - ref_time: 파일명에서 뽑은 기준 시각
    """
    tags: List[str] = []

    if base_dt is None:
        return tags

    # 1) 기본 TIME_* (ACCESSED / CREATED 중 하나)
    if use_access:
        tags.append("TIME_ACCESSED")
    else:
        tags.append("TIME_CREATED")

    # 2) ref_time 과 차이로 TIME_RECENT / WEEK / MONTH / OLD 중 하나
    if ref_time:
        diff_days = abs((ref_time - base_dt).total_seconds()) / 86400.0

        if diff_days <= 1:
            tags.append("TIME_RECENT")
        elif diff_days <= 7:
            tags.append("TIME_WEEK")
        elif diff_days <= 30:
            tags.append("TIME_MONTH")
        elif diff_days > 30:
            tags.append("TIME_OLD")

    return tags


# ===============================
# 3. FORMAT_ (다운로드된 파일 확장자 기반)
# ===============================

DOC_EXT = {".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt"}
XLS_EXT = {".xls", ".xlsx", ".csv"}
PPT_EXT = {".ppt", ".pptx"}
IMG_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg"}
VID_EXT = {".mp4", ".avi", ".mkv", ".mov", ".wmv"}
AUD_EXT = {".mp3", ".wav", ".flac", ".wma"}
ARC_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"}
EXE_EXT = {".exe", ".dll", ".sys", ".com", ".scr"}
SCR_EXT = {".ps1", ".bat", ".vbs", ".js", ".py", ".cmd"}
DB_EXT  = {".db", ".sqlite", ".accdb", ".mdb"}


def get_format_tags_from_target_path(target_path: str) -> List[str]:
    """
    TargetPath(다운로드된 파일 경로)의 확장자 기반 FORMAT_ 태그.
    - History DB 자체는 FORMAT_DATABASE 이므로 별도 추가.
    """
    tags: List[str] = []

    if not target_path:
        return tags

    _, ext = os.path.splitext(target_path)
    ext = ext.lower()

    if ext in DOC_EXT:
        tags.append("FORMAT_DOCUMENT")
    elif ext in XLS_EXT:
        tags.append("FORMAT_SPREADSHEET")
    elif ext in PPT_EXT:
        tags.append("FORMAT_PRESENTATION")
    elif ext in IMG_EXT:
        tags.append("FORMAT_IMAGE")
    elif ext in VID_EXT:
        tags.append("FORMAT_VIDEO")
    elif ext in AUD_EXT:
        tags.append("FORMAT_AUDIO")
    elif ext in ARC_EXT:
        tags.append("FORMAT_ARCHIVE")
    elif ext in EXE_EXT:
        tags.append("FORMAT_EXECUTABLE")
    elif ext in SCR_EXT:
        tags.append("FORMAT_SCRIPT")
    elif ext in DB_EXT:
        tags.append("FORMAT_DATABASE")

    return tags


# ===============================
# 4. Description 빌더
# ===============================

def build_description(row: Dict[str, str], lwt_field: Optional[str]) -> str:
    """
    - row: Downloads CSV 한 행
    - lwt_field: lastwritetimestemp로 사용한 필드명 ("LastAccessTime" 또는 "StartTime" 또는 None)

    규칙:
      - SourceFile 은 description에서 제외
      - lwt_field(LastWriteTimestamp로 쓴 컬럼)도 description에서 제외
      - 나머지 컬럼은 "Key:Value"로 " | " 로 이어붙임
    """
    parts: List[str] = []

    for key, val in row.items():
        if key == "SourceFile":
            continue
        if lwt_field and key == lwt_field:
            continue
        if val is None:
            continue
        s = str(val).strip()
        if not s:
            continue
        parts.append(f"{key}:{s}")

    return " | ".join(parts)


# ===============================
# 5. output 파일명 충돌 처리 (_v1, _v2 ...)
# ===============================

def ensure_unique_output_path(path: Path) -> Path:
    """
    이미 같은 이름의 파일이 있으면
    base_Tagged_v1.csv, base_Tagged_v2.csv ... 식으로
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


# ===============================
# 6. ccit 루트 찾기 (출력용)
# ===============================

def find_ccit_root(path: Path) -> Path:
    """
    입력 CSV가 있는 경로에서 위로 올라가면서
    이름이 'ccit' 인 폴더를 찾는다.
    못 찾으면 같은 드라이브의 'ccit' 폴더를 기본으로 사용.
    """
    for parent in [path] + list(path.parents):
        if parent.name.lower() == "ccit":
            return parent

    # fallback: 드라이브 루트 + ccit
    drive = path.drive or "D:"
    ccit_root = Path(drive + "\\ccit")
    ccit_root.mkdir(parents=True, exist_ok=True)
    return ccit_root


# ===============================
# 7. Downloads CSV → (type, lastwritetimestemp, descrition, tag)
# ===============================

def tag_downloads_csv(input_path: Path,
                      ref_time: Optional[datetime],
                      output_dir: Path) -> Path:
    """
    - input_path: ChromiumBrowser_Downloads CSV 전체 경로
    - ref_time: 파일명에서 뽑은 기준 시각
    - output_dir: 결과 CSV를 저장할 디렉터리

    출력 스키마:
      type, lastwritetimestemp, descrition, tag
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)
    output_filename = f"{base_no_ext}_Tagged.csv"
    output_path = ensure_unique_output_path(output_dir / output_filename)

    with input_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         output_path.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)
        fieldnames_out = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames_out)
        writer.writeheader()

        for row in reader:
            tags: List[str] = []

            # 1) 시간 필드 파싱
            start_str = row.get("StartTime", "") or ""
            access_str = row.get("LastAccessTime", "") or ""

            dt_start = parse_dt_generic(start_str)
            dt_access = parse_dt_generic(access_str)

            # LastWriteTimestamp용 필드 결정
            if dt_access:
                base_dt = dt_access
                lwt_field = "LastAccessTime"
                lwt_value = access_str
                use_access = True
            elif dt_start:
                base_dt = dt_start
                lwt_field = "StartTime"
                lwt_value = start_str
                use_access = False
            else:
                base_dt = None
                lwt_field = None
                lwt_value = ""
                use_access = False

            # 2) TIME_ 태그
            tags.extend(get_time_tags_for_download(base_dt, use_access, ref_time))

            # 3) ARTIFACT_ / AREA_ / ACT_ / EVENT_ / FORMAT_ / STATE_
            tags.append("ARTIFACT_BROWSER_DOWNLOAD")
            tags.append("ARTIFACT_DB")           # History DB 내부라서
            tags.append("AREA_APPDATA_LOCAL")    # SourceFile 경로 기준
            tags.append("ACT_DOWNLOAD")
            tags.append("ACT_BROWSING")
            tags.append("EVENT_CREATE")
            tags.append("STATE_ACTIVE")

            # History DB 자체 포맷
            tags.append("FORMAT_DATABASE")

            # TargetPath 기반 FORMAT_ 추가 (다운로드된 파일 확장자)
            target_path = row.get("TargetPath", "") or ""
            tags.extend(get_format_tags_from_target_path(target_path))

            # 4) descrition 생성
            description = build_description(row, lwt_field)

            # 5) Tag 정리 (중복 제거 + 정렬)
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            out_row = {
                "type": "ARTIFACT_BROWSER_DOWNLOAD",
                "lastwritetimestemp": lwt_value,
                "descrition": description,
                "tag": tag_str,
            }
            writer.writerow(out_row)

    return output_path


# ===============================
# 8. main (D:~Z: + ccit 스캔)
# ===============================

def main():
    print("[Downloads] D:~Z: + ccit 경로에서 *_ChromiumBrowser_Downloads_*.csv 탐색 중...")

    download_files = find_all_download_csv_under_ccit()
    if not download_files:
        print("[-] *_ChromiumBrowser_Downloads_*.csv 파일을 찾지 못했습니다.")
        return

    for input_path, ref_time in download_files:
        print(f"[+] 입력 파일: {input_path}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_* 태그는 일부 생략될 수 있음)")

        ccit_root = find_ccit_root(input_path)
        output_dir = ccit_root / "tagged"

        print(f"    -> 출력 디렉터리: {output_dir}")

        output_path = tag_downloads_csv(input_path, ref_time, output_dir)
        print(f"    -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(drive_letters, cfg) 형태로 호출해도 되고,
    단독 실행 시에는 main()만 쓰면 된다.
    여기서는 D:~Z: + ccit 스캔만 사용하므로 args/cfg는 무시한다.
    """
    main()


if __name__ == "__main__":
    main()
