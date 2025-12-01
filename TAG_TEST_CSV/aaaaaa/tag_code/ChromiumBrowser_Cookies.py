# -*- coding: utf-8 -*-
import os
import re
import csv
import argparse
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# ===============================
# 0. 유틸: 파일명에서 기준 시각(ref_time) 추출
# ===============================

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    r"""
    예: 20251114143910776344_ChromiumBrowser_Cookies_....csv
        -> 앞 14자리(20251114143910)만 잘라서 2025-11-14 14:39:10 로 변환
    """
    # 파일명만 추출
    name = os.path.basename(filename)

    # 앞에서부터 14자리 숫자 + 그 뒤에 'ChromiumBrowser_Cookies'가 들어가면 OK
    m = re.match(r"(\d{14}).*ChromiumBrowser_Cookies.*\.csv$", name)
    if not m:
        return None

    ts_str = m.group(1)  # 20251114143910
    try:
        return datetime.strptime(ts_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ===============================
# 1. base_dir 아래에서 최신 ChromiumBrowser_Cookies CSV 찾기
# ===============================

def find_latest_cookie_csv(base_dir: str) -> Tuple[Optional[str], Optional[datetime]]:
    """
    base_dir 아래를 재귀적으로 돌면서
    '*ChromiumBrowser_Cookies*.csv' 패턴을 모두 찾고,
    파일명 앞 14자리(YYYYMMDDHHMMSS) 기준으로 가장 최신 파일을 고른다.
    """
    candidate_files: List[Tuple[str, datetime]] = []

    for root, dirs, files in os.walk(base_dir):
        for name in files:
            if "ChromiumBrowser_Cookies" not in name:
                continue
            if not name.lower().endswith(".csv"):
                continue

            ref_time = parse_ref_time_from_filename(name)
            if ref_time is None:
                continue

            full_path = os.path.join(root, name)
            candidate_files.append((full_path, ref_time))

    if not candidate_files:
        return None, None

    candidate_files.sort(key=lambda x: x[1], reverse=True)
    latest_path, latest_ref_time = candidate_files[0]
    return latest_path, latest_ref_time


# ===============================
# 2. 시간 파싱 & TIME 태그
# ===============================

def parse_utc(ts_str: str) -> Optional[datetime]:
    """
    Cookies CSV의 CreationUTC / LastAccessUTC 문자열을 datetime으로 변환.
    예: '2025-09-12 8:17', '2025-10-13 06:06:30' 등 다양하게 들어와도 처리.
    """
    if not ts_str:
        return None

    s = ts_str.strip()
    if not s:
        return None

    # YYYY-MM-DD H(:)H:MM[:SS] 형태를 통으로 정규식으로 뽑아서 파싱
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
      TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 **정확히 하나** 붙인다.

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

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - LastAccessUTC는 LastWriteTimestamp에 이미 쓰므로 제외
      - SourceFile은 제외
      - 나머지 컬럼은 "Key:Value" 형태로 이어붙여 description 생성
    구분자: " | "
    """
    exclude_keys = {
        "LastAccessUTC",
        "SourceFile",
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

    return " | ".join(parts)



# ===============================
# 4. 쿠키용 태그 빌더
# ===============================

def build_cookie_tags(row: Dict[str, str],
                      ref_time: Optional[datetime]) -> List[str]:
    """
    한 쿠키 레코드(row)에 대해 태그 생성:
      - 기본 태그:
        ARTIFACT_BROWSER_COOKIE, AREA_APPDATA_LOCAL,
        FORMAT_DATABASE, ACT_BROWSING, STATE_ACTIVE
      - EVENT_CREATE: CreationUTC 있으면
      - TIME_*: LastAccessUTC 기준 (TIME_ACCESSED + RECENT/WEEK/MONTH/OLD 중 하나)
    """
    tags: List[str] = [
        "ARTIFACT_BROWSER_COOKIE",
        "AREA_APPDATA_LOCAL",
        "FORMAT_DATABASE",
        "ACT_BROWSING",
        "STATE_ACTIVE",
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

def ensure_unique_output_path(path: str) -> str:
    """
    이미 같은 이름의 파일이 있으면
    base_Tagged_v1.csv, base_Tagged_v2.csv ... 식으로
    사용 가능한 새 경로를 돌려준다.
    """
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    idx = 1
    while True:
        candidate = f"{base}_v{idx}{ext}"
        if not os.path.exists(candidate):
            return candidate
        idx += 1


# ===============================
# 6. ChromiumBrowser_Cookies CSV → 4컬럼 변환
# ===============================

def tag_cookie_csv(input_path: str,
                   ref_time: Optional[datetime],
                   output_dir: str) -> str:
    """
    - input_path: ChromiumBrowser_Cookies CSV 전체 경로
    - ref_time: 파일명에서 뽑은 기준 시각
    - output_dir: 결과 CSV 저장 디렉터리

    출력 스키마:
      Type, LastWriteTimestamp, description, tag
    """
    os.makedirs(output_dir, exist_ok=True)

    input_basename = os.path.basename(input_path)
    base_no_ext, _ = os.path.splitext(input_basename)
    output_filename = f"{base_no_ext}_Tagged.csv"
    output_path = os.path.abspath(os.path.join(output_dir, output_filename))
    output_path = ensure_unique_output_path(output_path)

    with open(input_path, "r", encoding="utf-8-sig", newline="") as f_in, \
         open(output_path, "w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)

        # 최종 출력 컬럼 4개
        fieldnames = ["Type", "LastWriteTimestamp", "description", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            # Type: 아티팩트 종류
            type_val = "ARTIFACT_BROWSER_COOKIE"

            # LastWriteTimestamp: LastAccessUTC 그대로 사용
            last_write_ts = (row.get("LastAccessUTC") or "").strip()

            # description: 나머지 컬럼 Key:Value | ... 로 합치기
            description = build_description(row)

            # tag: 우리가 정한 태그들
            tags = build_cookie_tags(row, ref_time)
            tag_str = ",".join(tags)

            out_row = {
                "Type": type_val,
                "LastWriteTimestamp": last_write_ts,
                "description": description,
                "tag": tag_str,
            }
            writer.writerow(out_row)

    return output_path


# ===============================
# 7. main: 스크립트 위치 기준 base_dir + csvtag_output
# ===============================

def main():
    parser = argparse.ArgumentParser(
        description="ChromiumBrowser_Cookies CSV를 4컬럼(Type, LastWriteTimestamp, description, tag)으로 변환하고 1차 태그를 부여하는 스크립트."
    )
    parser.add_argument(
        "--base-dir",
        type=str,
        default=None,
        help=(
            "ChromiumBrowser_Cookies CSV 파일을 찾을 기준 디렉터리. "
            "지정하지 않으면, 스크립트 기준 부모 폴더의 'Adware.Pushware Output' 폴더를 기준으로 재귀 탐색."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help=(
            "태깅된 CSV를 저장할 디렉터리. "
            "지정하지 않으면 스크립트 기준 부모 폴더의 'csvtag_output' 폴더를 사용."
        ),
    )

    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)

    args = parser.parse_args()

    if args.base_dir:
        base_dir = os.path.abspath(args.base_dir)
    else:
        # 여기서부터 os.walk 하니까,
        # Adware.Pushware Output 아래 H\SQLECmd 안에 있어도 자동으로 찾음
        base_dir = os.path.join(parent_dir, "Adware.Pushware Output")

    if args.output_dir:
        output_dir = os.path.abspath(args.output_dir)
    else:
        output_dir = os.path.join(parent_dir, "csvtag_output")

    print(f"[+] 검색 기준 디렉터리 (base_dir): {base_dir}")
    print(f"[+] 결과 저장 디렉터리 (output_dir): {output_dir}")

    input_path, ref_time = find_latest_cookie_csv(base_dir)
    if not input_path or not ref_time:
        print("[-] ChromiumBrowser_Cookies CSV 파일을 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
        return

    print(f"[+] 선택된 입력 파일: {os.path.abspath(input_path)}")
    print(f"[+] 파일명 기준 기준 시각(ref_time): {ref_time}")

    output_path = tag_cookie_csv(input_path, ref_time, output_dir)

    print(f"[+] 태깅/변환 완료. 결과 파일: {output_path}")


if __name__ == "__main__":
    main()
