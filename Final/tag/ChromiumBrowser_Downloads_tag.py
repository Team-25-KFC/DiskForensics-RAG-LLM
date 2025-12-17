# -*- coding: utf-8 -*-
import os
import csv
import shutil
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path

# ===============================
# 0. 날짜/시간 파서 & TIME 버킷 계산
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

    for fmt in ("%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

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
    - ref_time: 기준 시각
    """
    tags: List[str] = []

    if base_dt is None:
        return tags

    # 1) 기본 TIME_ (ACCESSED / CREATED 중 하나)
    if use_access:
        tags.append("TIME_ACCESSED")
    else:
        tags.append("TIME_CREATED")

    # 2) ref_time 과 차이로 TIME_RECENT / WEEK / MONTH / OLD
    if ref_time:
        diff_days = abs((ref_time - base_dt).total_seconds()) / 86400.0

        if diff_days <= 1:
            tags.append("TIME_RECENT")
        elif diff_days <= 7:
            tags.append("TIME_WEEK")
        elif diff_days <= 30:
            tags.append("TIME_MONTH")
        else:
            tags.append("TIME_OLD")

    return tags


# ===============================
# 1. Kape Output 아래에서 Downloads CSV 찾기
# ===============================

def find_kape_downloads_csvs() -> List[Path]:
    """
    D:~Z: 전체를 돌면서
    '드라이브 루트\\Kape Output' 아래에서
    '*ChromiumBrowser_Downloads*.csv' 파일을 찾는다.
    """
    results: List[Path] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = drive_root / "Kape Output"
        if not kape_root.exists():
            continue

        for root, dirs, files in os.walk(str(kape_root)):
            for name in files:
                lower = name.lower()
                if "chromiumbrowser_downloads" not in lower:
                    continue
                if not lower.endswith(".csv"):
                    continue

                full_path = Path(root) / name
                results.append(full_path)
                print(f"[DEBUG] KAPE Downloads CSV 발견: {full_path}")

    if not results:
        print("[-] 'Kape Output' 아래에서 ChromiumBrowser_Downloads CSV를 찾지 못했습니다.")

    return results


def derive_ref_time_for_downloads(csv_path: Path) -> Optional[datetime]:
    """
    CSV 안에서 가장 먼저 나오는 유효한 LastAccessTime / StartTime을 ref_time으로 사용.
    없으면 None.
    """
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                access_str = row.get("LastAccessTime", "") or ""
                start_str = row.get("StartTime", "") or ""

                dt_access = parse_dt_generic(access_str)
                dt_start = parse_dt_generic(start_str)

                if dt_access:
                    return dt_access
                if dt_start:
                    return dt_start

        return None
    except Exception as e:
        print(f"[WARN] ref_time 추출 중 오류 발생: {csv_path} -> {e}")
        return None


# ===============================
# 2. FORMAT_ (다운로드된 파일 확장자 기반)
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
# 3. Description 빌더
# ===============================

def build_description(row: Dict[str, str],
                      lwt_field: Optional[str],
                      extra: Optional[Dict[str, str]] = None) -> str:
    """
    - row: Downloads CSV 한 행
    - lwt_field: lastwritetimestemp로 사용한 필드명 ("LastAccessTime" 또는 "StartTime" 또는 None)
    - extra: CsvPath, CsvName 등 추가 정보

    규칙:
      - lwt_field(LastWriteTimestamp로 쓴 컬럼)만 description에서 제외
      - SourceFile 은 포함 (어디 히스토리 DB인지)
      - 나머지 컬럼은 "Key:Value"로 " | " 로 이어붙임
    """
    parts: List[str] = []

    for key, val in row.items():
        if lwt_field and key == lwt_field:
            continue
        if val is None:
            continue
        s = str(val).strip()
        if not s:
            continue
        parts.append(f"{key}:{s}")

    if extra:
        for key, val in extra.items():
            if val is None:
                continue
            s = str(val).strip()
            if not s:
                continue
            parts.append(f"{key}:{s}")

    return " | ".join(parts)


# ===============================
# 4. output 파일명 충돌 처리 (_v1, _v2 ...)
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
# 5. ccit 루트 찾기 (artifact_csv용)
# ===============================

def find_ccit_root(path: Path) -> Path:
    """
    입력 경로에서 위로 올라가면서 이름이 'ccit'인 폴더를 찾는다.
    없으면 같은 드라이브 루트에 'ccit'를 생성해서 사용.
    """
    for parent in [path] + list(path.parents):
        if parent.name.lower() == "ccit":
            return parent

    drive = path.drive or "D:"
    ccit_root = Path(drive + "\\ccit")
    ccit_root.mkdir(parents=True, exist_ok=True)
    return ccit_root


# ===============================
# 6. Kape Output 하위 1단계 폴더명 추출
# ===============================

def get_kape_child_name(src_path: Path) -> str:
    """
    예: D:\\Kape Output\\G\\SQLECmd\\...
      -> 'G' 를 돌려줌.
    못 찾으면 'KAPE' 리턴.
    """
    for parent in [src_path] + list(src_path.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = src_path.relative_to(parent)
                if len(rel.parts) > 1:
                    return rel.parts[0]
                else:
                    return "KAPE"
            except ValueError:
                continue
    return "KAPE"


# ===============================
# 7. Downloads CSV → (type, lastwritetimestemp, descrition, tag)
# ===============================

def tag_downloads_csv(input_path: Path,
                      ref_time: Optional[datetime],
                      output_dir: Path,
                      kape_child: Optional[str] = None) -> Path:
    """
    - input_path: artifact_csv 안으로 복사된 ChromiumBrowser_Downloads CSV
    - ref_time: 기준 시각
    - output_dir: 결과 CSV를 저장할 'tagged' 디렉터리 (ccit와 같은 레벨)
    - kape_child: Kape Output 바로 아래 폴더명 (예: 'G')

    출력 스키마:
      type, lastwritetimestemp, descrition, tag
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)

    label = (kape_child or "").strip()
    if label:
        output_filename = f"{label}_{base_no_ext}_Tagged.csv"
    else:
        output_filename = f"{base_no_ext}_Tagged.csv"

    output_path = ensure_unique_output_path(output_dir / output_filename)

    with input_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         output_path.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)
        fieldnames_out = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames_out)
        writer.writeheader()

        extra_common = {
            "CsvPath": str(input_path),
            "CsvName": input_basename,
        }

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
            tags.append("ARTIFACT_DB")           # History DB 내부
            tags.append("AREA_APPDATA_LOCAL")    # SourceFile 경로 기준
            tags.append("ACT_DOWNLOAD")
            tags.append("ACT_BROWSING")
            tags.append("EVENT_BROWSER_DOWNLOAD")  # 다운로드 이벤트
            tags.append("STATE_ACTIVE")

            # History DB 자체 포맷
            tags.append("FORMAT_DATABASE")

            # TargetPath 기반 FORMAT_ 추가 (다운로드된 파일 확장자)
            target_path = row.get("TargetPath", "") or ""
            tags.extend(get_format_tags_from_target_path(target_path))

            # 4) descrition 생성 (행 데이터 + CsvPath/CsvName)
            description = build_description(row, lwt_field, extra=extra_common)

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
# 8. main (Kape Output → ccit\\artifact_csv → tagged)
# ===============================

def main():
    print("[Downloads] D:~Z: 의 'Kape Output' 아래에서 ChromiumBrowser_Downloads CSV 탐색 중...")

    kape_csvs = find_kape_downloads_csvs()
    if not kape_csvs:
        return

    copied_list: List[Tuple[Path, datetime, str]] = []

    # 1단계: 원본 KAPE CSV → ccit\\artifact_csv 로 복사 + ref_time 계산
    for src_path in kape_csvs:
        print(f"[+] 원본 KAPE Downloads CSV: {src_path}")

        ref_time = derive_ref_time_for_downloads(src_path)
        if ref_time:
            print(f"    -> ref_time(다운로드 시각 기준): {ref_time}")
        else:
            ref_time = datetime.fromtimestamp(src_path.stat().st_mtime)
            print(f"    -> ref_time 없음, 파일 mtime 사용: {ref_time}")

        kape_child = get_kape_child_name(src_path)
        print(f"    -> Kape 하위 폴더 라벨: {kape_child}")

        ccit_root = find_ccit_root(src_path)

        artifact_dir = ccit_root / "artifact_csv"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        prefix = ref_time.strftime("%Y%m%d%H%M%S")
        new_name = f"{prefix}_{src_path.name}"
        dest_path = ensure_unique_output_path(artifact_dir / new_name)

        shutil.copy2(src_path, dest_path)
        print(f"    -> artifact_csv 복사/이름변경: {dest_path}")

        copied_list.append((dest_path, ref_time, kape_child))

    # 2단계: artifact_csv → tagged (ccit와 같은 레벨의 tagged 폴더)
    for artifact_path, ref_time, kape_child in copied_list:
        ccit_root = find_ccit_root(artifact_path)
        output_dir = ccit_root.parent / "tagged"   # 예: D:\\ccit -> D:\\tagged

        print(f"[TAG] 입력 파일: {artifact_path}")
        print(f"      출력 디렉터리: {output_dir}")

        output_path = tag_downloads_csv(
            artifact_path,
            ref_time,
            output_dir,
            kape_child=kape_child,
        )
        print(f"      -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(drive_letters, cfg) 형태로 호출해도 되고,
    단독 실행 시에는 main()만 쓰면 된다.
    """
    main()


if __name__ == "__main__":
    main()
