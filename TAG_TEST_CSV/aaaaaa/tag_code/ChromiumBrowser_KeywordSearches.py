# -*- coding: utf-8 -*-
import os
import re
import csv
import argparse
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# =========================================
# 0. 공통: 시간 파싱 유틸
# =========================================

def parse_utc_time(s: str) -> Optional[datetime]:
    """
    ChromiumBrowser_KeywordSearches 의 LastVisitTime 같은 문자열을 datetime으로 변환.
    - 빈 값이면 None
    - 1601-01-01 00:00:00 같은 초기값(Null 의미)도 None 처리
    - 몇 가지 대표 형식을 순차적으로 시도
    """
    if s is None:
        return None

    s = s.strip()
    if not s:
        return None

    # 크롬/SQLite 기본 null값(사실상 의미 없는 타임스탬프)은 버린다
    if s.startswith("1601-01-01"):
        return None

    # 시도할 포맷들
    candidates = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    # 그래도 안 되면 포기
    return None


def get_time_window_tags(event_dt: Optional[datetime],
                         ref_time: Optional[datetime]) -> List[str]:
    """
    ref_time - event_dt 차이를 보고
    TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나만 돌려준다.
    둘 중 하나라도 없으면 빈 리스트.
    규칙:
      - ≤ 1일    -> TIME_RECENT
      - ≤ 7일    -> TIME_WEEK
      - ≤ 30일   -> TIME_MONTH
      - 30일 초과 -> TIME_OLD
    """
    if not event_dt or not ref_time:
        return []

    diff = ref_time - event_dt
    days = abs(diff.total_seconds()) / 86400.0  # 일 단위 절댓값

    if days <= 1:
        return ["TIME_RECENT"]
    elif days <= 7:
        return ["TIME_WEEK"]
    elif days <= 30:
        return ["TIME_MONTH"]
    else:  # 30일 초과 -> TIME_OLD
        return ["TIME_OLD"]


def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    파일명 맨 앞 14자리가 YYYYMMDDHHMMSS 형식이라고 가정하고 파싱.
    예: 20251114143911_ChromiumBrowser_KeywordSearches_....csv
         -> "20251114143911"만 잘라서 기준 시각으로 사용.
    """
    if len(filename) < 14:
        return None

    prefix = filename[:14]
    if not prefix.isdigit():
        return None

    try:
        return datetime.strptime(prefix, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# =========================================
# 1. base_dir 아래에서 KeywordSearches CSV 찾기
# =========================================

def find_keywordsearch_csvs(base_dir: str) -> List[Tuple[str, Optional[datetime]]]:
    """
    base_dir 아래를 재귀적으로 돌면서
    '*_ChromiumBrowser_KeywordSearches_*.csv' 패턴을 모두 찾고,
    각 파일 경로와 파일명 기준 시각(ref_time)을 리스트로 돌려준다.
    """
    results: List[Tuple[str, Optional[datetime]]] = []

    for root, dirs, files in os.walk(base_dir):
        for name in files:
            # 파일명 패턴 필터
            if "_ChromiumBrowser_KeywordSearches_" not in name:
                continue
            if not name.lower().endswith(".csv"):
                continue

            full_path = os.path.join(root, name)
            ref_time = parse_ref_time_from_filename(name)

            if ref_time is None:
                print(f"[DEBUG] KeywordSearches 후보 파일이지만 날짜 파싱 실패: {name}")
            else:
                print(f"[DEBUG] KeywordSearches 후보 파일: {name}, ref_time={ref_time}")

            results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] KeywordSearches 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] KeywordSearches 후보 파일 개수: {len(results)}")

    return results


# =========================================
# 2. Description 빌더
# =========================================

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - KeywordID, URLID, LastVisitTime, LastVisitTime (UTC), SourceFile 은 description에서 제외
      - 나머지를 "Key:Value" 형태로 이어붙여 Description 생성
    구분자: " | "
    """
    exclude_keys = {
        "KeywordID",
        "URLID",
        "LastVisitTime",
        "LastVisitTime (UTC)",
        "SourceFile",   # 완전히 버린다
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


# =========================================
# 3. output 파일명 충돌 처리 (_v1, _v2 ...)
# =========================================

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


# =========================================
# 4. KeywordSearches CSV 태깅 (Type / LastWriteTimestamp / Description / Tags)
# =========================================

def tag_keywordsearches_csv(input_path: str,
                            ref_time: Optional[datetime],
                            output_dir: str) -> str:
    """
    ChromiumBrowser_KeywordSearches CSV 한 개를 태깅해서

    Type, LastWriteTimestamp, Description, Tags

    4컬럼 형태로 변환해서 저장한다.
    - Type: "ChromiumBrowser_KeywordSearches" 고정
    - LastWriteTimestamp: LastVisitTime(또는 LastVisitTime (UTC)) 문자열 사용
    - Description:
        KeywordID, URLID, LastVisitTime 계열, SourceFile 을 제외하고
        "Key:Value | Key2:Value2 ..." 형식으로 합침
    - Tags:
        ARTIFACT_BROWSER_HISTORY
        AREA_APPDATA_LOCAL
        ACT_SEARCH
        ACT_BROWSING
        EVENT_ACCESSED
        STATE_ACTIVE
        + TIME_ACCESSED (LastVisitTime가 유효할 때)
        + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 (ref_time 기준)
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

        # 최종 출력 컬럼 4개만
        fieldnames = ["Type", "LastWriteTimestamp", "Description", "Tags"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            tags: List[str] = []

            # --- 기본 태그 ---
            tags.append("ARTIFACT_BROWSER_HISTORY")
            tags.append("AREA_APPDATA_LOCAL")
            tags.append("ACT_SEARCH")
            tags.append("ACT_BROWSING")
            tags.append("EVENT_ACCESSED")
            tags.append("STATE_ACTIVE")

            # ===========================
            # ① LastVisitTime 기반 시간 태그
            # ===========================
            raw_last_visit = (
                row.get("LastVisitTime", "")
                or row.get("LastVisitTime (UTC)", "")
            )

            last_visit_dt = parse_utc_time(raw_last_visit)
            last_write_ts = raw_last_visit.strip() if raw_last_visit else ""

            if last_visit_dt:
                tags.append("TIME_ACCESSED")
                tags.extend(get_time_window_tags(last_visit_dt, ref_time))

            # ===========================
            # ② Description 생성
            # ===========================
            description = build_description(row)

            # ===========================
            # ③ 태그 정리 & 출력
            # ===========================
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            output_row = {
                "Type": "ChromiumBrowser_KeywordSearches",
                "LastWriteTimestamp": last_write_ts,
                "Description": description,
                "Tags": tag_str,
            }
            writer.writerow(output_row)

    return output_path


# =========================================
# 5. main
# =========================================

def main():
    parser = argparse.ArgumentParser(
        description="ChromiumBrowser_KeywordSearches CSV에 1차 태그를 자동으로 부여하는 스크립트."
    )
    parser.add_argument(
        "--base-dir",
        type=str,
        default=None,
        help=(
            "*_ChromiumBrowser_KeywordSearches_*.csv 파일을 찾을 기준 디렉터리. "
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
        base_dir = os.path.join(parent_dir, "Adware.Pushware Output")

    if args.output_dir:
        output_dir = os.path.abspath(args.output_dir)
    else:
        output_dir = os.path.join(parent_dir, "csvtag_output")

    print(f"[+] 검색 기준 디렉터리 (base_dir): {base_dir}")
    print(f"[+] 결과 저장 디렉터리 (output_dir): {output_dir}")

    candidates = find_keywordsearch_csvs(base_dir)
    if not candidates:
        print("[-] *_ChromiumBrowser_KeywordSearches_*.csv 파일을 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
        return

    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {os.path.abspath(input_path)}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략됨)")

        output_path = tag_keywordsearches_csv(input_path, ref_time, output_dir)
        print(f"[+] 태깅 완료. 결과 파일: {output_path}")


if __name__ == "__main__":
    main()
