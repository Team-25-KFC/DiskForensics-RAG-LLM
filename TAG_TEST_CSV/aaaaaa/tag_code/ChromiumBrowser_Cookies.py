# -*- coding: utf-8 -*-
"""
ChromiumBrowser_Cookies CSV 정규화 + 태깅 모듈

[동작 요약]

- D:~Z: 각 드라이브 루트에서
    "<드라이브>:\\Kape Output" 아래를 재귀 탐색한다.
- 그 아래에서 "*ChromiumBrowser_Cookies*.csv" 파일들을 모두 찾는다.
- 각 파일에 대해:
    1) 파일명 앞 14자리(YYYYMMDDHHMMSS)로 ref_time 추출
       (없으면 파일 수정 시간(mtime)을 ref_time으로 사용)
    2) "Kape Output" 바로 아래 1단계 폴더 이름(예: G, H, ...)을 라벨로 추출
    3) 해당 드라이브의 "<드라이브>:\\ccit\\artifact_csv"로
       "YYYYMMDDHHMMSS_원본파일명.csv" 형태로 복사
    4) "<드라이브>:\\tagged" 폴더에
       "<KapeChild>_YYYYMMDDHHMMSS_원본파일명_Tagged.csv"로 태깅 결과 저장

출력 스키마(공통):
  type, lastwritetimestemp, descrition, tag
"""

import os
import re
import csv
import shutil
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# ===============================
# 0. 파일명에서 기준 시각(ref_time) 추출
# ===============================

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    예:
        20251114143910_ChromiumBrowser_Cookies_....csv
        20251114143910567890_ChromiumBrowser_Cookies_....csv

    앞쪽의 연속된 14자리 숫자(YYYYMMDDHHMMSS)를 찾아 ref_time으로 사용.
    """
    name = os.path.basename(filename)

    m = re.match(r"(\d{14})", name)
    if not m:
        return None

    ts_str = m.group(1)
    try:
        return datetime.strptime(ts_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ===============================
# 1. Kape Output 아래에서 Cookies CSV 찾기
# ===============================

def find_kape_cookie_csvs() -> List[Path]:
    """
    D:~Z: 각 드라이브에서 "<드라이브>:\\Kape Output" 아래를 탐색해
    "*ChromiumBrowser_Cookies*.csv" 파일들을 찾는다.
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
                if "chromiumbrowser_cookies" not in lower:
                    continue
                if not lower.endswith(".csv"):
                    continue

                full_path = Path(root) / name
                results.append(full_path)
                print(f"[DEBUG] KAPE Cookies CSV 발견: {full_path}")

    if not results:
        print("[-] 'Kape Output' 아래에서 ChromiumBrowser_Cookies CSV를 찾지 못했습니다.")

    return results


def get_kape_child_name(src_path: Path) -> str:
    """
    예: D:\\Kape Output\\G\\SQLECmd\\... -> 'G' 반환.
    못 찾으면 'KAPE' 리턴.
    """
    for parent in [src_path] + list(src_path.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = src_path.relative_to(parent)
                if len(rel.parts) > 0:
                    return rel.parts[0]
                else:
                    return "KAPE"
            except ValueError:
                continue
    return "KAPE"


# ===============================
# 2. 시간 파싱 & TIME 태그
# ===============================

def parse_utc(ts_str: str) -> Optional[datetime]:
    """
    Cookies CSV의 CreationUTC / LastAccessUTC 문자열을 datetime으로 변환.
    예: '2025-09-12 8:17', '2025-10-13 06:06:30' 등 다양한 패턴 처리.
    """
    if not ts_str:
        return None

    s = ts_str.strip()
    if not s:
        return None

    m = re.search(
        r"(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?",
        s
    )
    if not m:
        return None

    year, month, day, hour, minute, sec = m.groups()
    if sec is None:
        sec = "0"

    try:
        return datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(sec),
        )
    except ValueError:
        return None


def get_time_tags(last_access: Optional[datetime],
                  ref_time: Optional[datetime]) -> List[str]:
    """
    - last_access가 존재하면: TIME_ACCESSED
    - ref_time 과 last_access 차이를 기준으로
      TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 정확히 하나 부여

        * TIME_RECENT : 1일(24시간) 이내
        * TIME_WEEK   : 7일 이내
        * TIME_MONTH  : 31일 이내
        * TIME_OLD    : 31일 초과
    """
    tags: List[str] = []

    if last_access:
        tags.append("TIME_ACCESSED")

    if last_access and ref_time:
        diff = ref_time - last_access
        days = abs(diff.total_seconds()) / 86400.0

        if days <= 1:
            tags.append("TIME_RECENT")
        elif days <= 7:
            tags.append("TIME_WEEK")
        elif days <= 31:
            tags.append("TIME_MONTH")
        else:
            tags.append("TIME_OLD")

    return tags


# ===============================
# 3. description 빌더
# ===============================

def build_description(row: Dict[str, str],
                      extra: Optional[Dict[str, str]] = None) -> str:
    """
    한 행(row)에서:
      - LastAccessUTC는 lastwritetimestemp에 이미 쓰므로 제외
      - SourceFile은 그대로 둔다 (어디 히스토리 DB인지 알 수 있음)
      - 나머지 컬럼은 "Key:Value" 형태로 이어붙여 description 생성
      - extra(CsvPath, CsvName 등)가 들어오면 마지막에 붙인다.
    구분자: " | "
    """
    exclude_keys = {
        "LastAccessUTC",
    }

    parts: List[str] = []
    for key, val in row.items():
        if key in exclude_keys:
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
# 4. 쿠키용 태그 빌더
# ===============================

def build_cookie_tags(row: Dict[str, str],
                      ref_time: Optional[datetime]) -> List[str]:
    """
    한 쿠키 레코드(row)에 대해 태그 생성:
      - 기본 태그:
        ARTIFACT_BROWSER_COOKIE
        AREA_APPDATA_LOCAL
        FORMAT_DATABASE
        ACT_BROWSING
        STATE_ACTIVE
        EVENT_BROWSER_COOKIE_ACCESS   ← 쿠키 접근/사용
      - EVENT_CREATE: CreationUTC 있으면
      - TIME_*: LastAccessUTC 기준 (TIME_ACCESSED + RECENT/WEEK/MONTH/OLD 중 하나)
    """
    tags: List[str] = [
        "ARTIFACT_BROWSER_COOKIE",
        "AREA_APPDATA_LOCAL",
        "FORMAT_DATABASE",
        "ACT_BROWSING",
        "STATE_ACTIVE",
        "EVENT_BROWSER_COOKIE_ACCESS",
    ]

    # EVENT_CREATE (생성 기준)
    creation_dt = parse_utc(row.get("CreationUTC", ""))
    if creation_dt:
        tags.append("EVENT_CREATE")

    # TIME_* (LastAccess 기준)
    last_access_dt = parse_utc(row.get("LastAccessUTC", ""))
    tags.extend(get_time_tags(last_access_dt, ref_time))

    # 중복 제거 + 정렬
    return sorted(set(tags))


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
# 6. ccit 루트 찾기 (artifact_csv용)
# ===============================

def find_ccit_root(path: Path) -> Path:
    """
    입력 경로에서 위로 올라가면서
    이름이 'ccit' 인 폴더를 찾는다.
    못 찾으면 같은 드라이브의 'ccit' 폴더를 기본으로 사용.
    """
    for parent in [path] + list(path.parents):
        if parent.name.lower() == "ccit":
            return parent

    drive = path.drive or "D:"
    ccit_root = Path(drive + "\\ccit")
    ccit_root.mkdir(parents=True, exist_ok=True)
    return ccit_root


# ===============================
# 7. ChromiumBrowser_Cookies CSV → 4컬럼 변환
# ===============================

def tag_cookie_csv(input_path: Path,
                   ref_time: Optional[datetime],
                   output_dir: Path,
                   kape_child: Optional[str] = None) -> Path:
    """
    - input_path: ccit\\artifact_csv 안에 있는 정규화된 Cookies CSV
    - ref_time : 기준 시각
    - output_dir: 결과 CSV 저장 디렉터리 (드라이브 루트의 tagged)
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

        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        extra_common = {
            "CsvPath": str(input_path),
            "CsvName": input_basename,
        }

        for row in reader:
            type_val = "ARTIFACT_BROWSER_COOKIE"

            # lastwritetimestemp: LastAccessUTC 그대로 사용
            last_write_ts = (row.get("LastAccessUTC") or "").strip()

            # descrition: 행 + CsvPath/CsvName
            description = build_description(row, extra=extra_common)

            # tag: 태그 리스트
            tags = build_cookie_tags(row, ref_time)
            tag_str = ",".join(tags)

            out_row = {
                "type": type_val,
                "lastwritetimestemp": last_write_ts,
                "descrition": description,
                "tag": tag_str,
            }
            writer.writerow(out_row)

    return output_path


# ===============================
# 8. main (Kape Output → ccit\\artifact_csv → 드라이브 루트\\tagged)
# ===============================

def main():
    print("[ChromiumCookies] D:~Z: 의 'Kape Output' 아래에서 ChromiumBrowser_Cookies CSV 탐색 중...")

    kape_csvs = find_kape_cookie_csvs()
    if not kape_csvs:
        return

    copied_list: List[Tuple[Path, datetime, str]] = []

    # 1단계: 원본 KAPE CSV → ccit\\artifact_csv 로 복사 + ref_time 계산
    for src_path in kape_csvs:
        print(f"[+] 원본 KAPE Cookies CSV: {src_path}")

        ref_time = parse_ref_time_from_filename(src_path.name)
        if ref_time:
            print(f"    -> 파일명 기준 ref_time: {ref_time}")
        else:
            ref_time = datetime.fromtimestamp(src_path.stat().st_mtime)
            print(f"    -> 파일명에서 ref_time 추출 실패, mtime 사용: {ref_time}")

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

    # 2단계: artifact_csv → tagged (드라이브 루트의 tagged 폴더)
    for artifact_path, ref_time, kape_child in copied_list:
        ccit_root = find_ccit_root(artifact_path)
        # ccit와 같은 레벨에 tagged 생성: 예) D:\\ccit -> D:\\tagged
        output_dir = ccit_root.parent / "tagged"

        print(f"[TAG] 입력 파일: {artifact_path}")
        print(f"      출력 디렉터리: {output_dir}")

        output_path = tag_cookie_csv(
            artifact_path,
            ref_time,
            output_dir,
            kape_child=kape_child,
        )
        print(f"      -> 태깅 완료. 결과 파일: {output_path}")


# 오케스트레이터용 엔트리
def run(*args, **kwargs):
    main()


if __name__ == "__main__":
    main()
