# -*- coding: utf-8 -*-
import os
import re
import csv
import argparse
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# =========================================
# 0. 파일명에서 기준 시각(ref_time) 추출
#    예: 20251114143911587892_ChromiumBrowser_HistoryVisits_....csv
#         -> 2025-11-14 14:39:11
# =========================================

def parse_utc_time(s: str) -> Optional[datetime]:
    """
    HistoryVisits의 'LastVisitedTime (UTC)' 같은 문자열을 datetime으로 변환.
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
    elif days > 30:
        return ["TIME_OLD"]
    else:
        # 30~90일 사이면 굳이 안 붙이는 정책이면 여기서 빈 리스트
        return []


    return tags
def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    파일명 맨 앞 14자리가 YYYYMMDDHHMMSS 형식이라고 가정하고 파싱.
    예: 20251114143911587892_ChromiumBrowser_HistoryVisits_....csv
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
# 1. base_dir 아래에서 최신 HistoryVisits CSV 찾기
# =========================================

def find_historyvisits_csvs(base_dir: str) -> List[Tuple[str, Optional[datetime]]]:
    """
    base_dir 아래를 재귀적으로 돌면서
    '*_ChromiumBrowser_HistoryVisits_*.csv' 패턴을 모두 찾고,
    각 파일 경로와 파일명 기준 시각(ref_time)을 리스트로 돌려준다.
    """
    results: List[Tuple[str, Optional[datetime]]] = []

    for root, dirs, files in os.walk(base_dir):
        for name in files:
            # 파일명 패턴 필터
            if "_ChromiumBrowser_HistoryVisits_" not in name:
                continue
            if not name.lower().endswith(".csv"):
                continue

            full_path = os.path.join(root, name)
            ref_time = parse_ref_time_from_filename(name)

            if ref_time is None:
                print(f"[DEBUG] HistoryVisits 후보 파일이지만 날짜 파싱 실패: {name}")
            else:
                print(f"[DEBUG] HistoryVisits 후보 파일: {name}, ref_time={ref_time}")

            results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] HistoryVisits 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] HistoryVisits 후보 파일 개수: {len(results)}")

    return results


# =========================================
# 2. 시간 파싱 & TIME 태그 계산
# =========================================

def parse_utc_datetime(dt_str: str) -> Optional[datetime]:
    """
    'YYYY-MM-DD HH:MM:SS' 또는 'YYYY-MM-DD HH:MM' 같은 문자열을 datetime으로 변환.
    크롬의 1601-01-01 00:00:00 같은 값은 '유효하지 않은 시간'으로 보고 None 처리.
    """
    if not dt_str:
        return None

    s = dt_str.strip()
    if not s:
        return None

    # 크롬 기본값(미사용) 처리
    if s.startswith("1601-01-01"):
        return None

    # 공백, T 섞여 있을 수 있으니 T -> 공백
    s = s.replace("T", " ")

    # 초까지 있는 케이스
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def get_time_tags(last_dt: Optional[datetime],
                  ref_time: Optional[datetime]) -> List[str]:
    """
    - last_dt(LastVisitedTime)가 존재하면: TIME_ACCESSED
    - ref_time 과 last_dt 차이 절댓값 기준으로
      TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나만 추가
    """
    tags: List[str] = []
    if last_dt:
        tags.append("TIME_ACCESSED")

    if last_dt and ref_time:
        diff = ref_time - last_dt
        days = abs(diff.total_seconds()) / 86400.0

        if days <= 1:
            tags.append("TIME_RECENT")
        elif days <= 7:
            tags.append("TIME_WEEK")
        elif days <= 30:
            tags.append("TIME_MONTH")
        elif days > 90:
            tags.append("TIME_OLD")

    return tags


# =========================================
# 3. Description 빌더
# =========================================

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - ID, VisitID, FromVisitID, LastVisitedTime (UTC), SourceFile 은 description에서 제외
      - 나머지를 "Key:Value" 형태로 이어붙여 Description 생성
    구분자: " | "
    """
    exclude_keys = {
        "ID",
        "VisitID",
        "FromVisitID",
        "LastVisitedTime (UTC)",
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


# =========================================
# 4. output 파일명 충돌 처리 (_v1, _v2 ...)
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
# 5. HistoryVisits CSV 태깅 (정규화: Type / LastWriteTimestamp / Description / Tag)
# =========================================

def tag_historyvisits_csv(input_path: str,
                          ref_time: Optional[datetime],
                          output_dir: str) -> str:
    """
    ChromiumBrowser_HistoryVisits CSV 한 개를 태깅해서

    Type, LastWriteTimestamp, Description, Tags

    4컬럼 형태로 변환해서 저장한다.
    - Type: "ChromiumBrowser_HistoryVisits" 고정
    - LastWriteTimestamp: LastVisitedTime (UTC)를 그대로 문자열로 사용
    - Description: ID/VisitID/FromVisitID/SourceFile/LastVisitedTime 컬럼 제외하고
                   "Key:Value | Key2:Value2 ..." 형식으로 합침
    - Tags:
        ARTIFACT_BROWSER_HISTORY
        AREA_APPDATA_LOCAL
        ACT_BROWSING
        EVENT_ACCESSED
        STATE_ACTIVE
        + TIME_ACCESSED (LastVisitedTime가 유효할 때)
        + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 (ref_time 기준)
    """
    # 출력 폴더 생성
    os.makedirs(output_dir, exist_ok=True)

    # ===== output_path 정의 (여기 때문에 NameError 났던 부분) =====
    input_basename = os.path.basename(input_path)
    base_no_ext, _ = os.path.splitext(input_basename)
    output_filename = f"{base_no_ext}_Tagged.csv"
    output_path = os.path.abspath(os.path.join(output_dir, output_filename))
    output_path = ensure_unique_output_path(output_path)
    # ========================================================

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
            tags.append("ACT_BROWSING")
            tags.append("EVENT_ACCESSED")
            tags.append("STATE_ACTIVE")

            # ===========================
            # ① LastVisitedTime 기반 시간 태그
            # ===========================
            raw_last_visited = (
                row.get("LastVisitedTime (UTC)", "")
                or row.get("LastVisitedTime", "")
            )

            last_visited_dt = parse_utc_time(raw_last_visited)

            # LastWriteTimestamp 컬럼에 들어갈 문자열 (그대로 사용)
            last_write_ts = raw_last_visited.strip() if raw_last_visited else ""

            # TIME_ACCESSED + 구간 태그(TIME_RECENT/WEEK/MONTH/OLD 중 하나)
            if last_visited_dt:
                tags.append("TIME_ACCESSED")
                tags.extend(get_time_window_tags(last_visited_dt, ref_time))


            # ===========================
            # ② Description 빌드
            #    ID / VisitID / FromVisitID / SourceFile / LastVisitedTime 계열은 제외
            # ===========================
            desc_parts: List[str] = []
            for key, val in row.items():
                if key in (
                    "ID",
                    "VisitID",
                    "FromVisitID",
                    "SourceFile",
                    "LastVisitedTime (UTC)",
                    "LastVisitedTime",
                ):
                    continue
                if val is None:
                    continue
                s = str(val).strip()
                if not s:
                    continue
                desc_parts.append(f"{key}:{s}")

            description = " | ".join(desc_parts)

            # ===========================
            # ③ 태그 정리 & 최종 레코드 작성
            # ===========================
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            output_row = {
                "Type": "ChromiumBrowser_HistoryVisits",
                "LastWriteTimestamp": last_write_ts,
                "Description": description,
                "Tags": tag_str,
            }
            writer.writerow(output_row)

    return output_path




# =========================================
# 6. main
# =========================================

def main():
    parser = argparse.ArgumentParser(
        description="ChromiumBrowser_HistoryVisits CSV에 1차 태그를 자동으로 부여하는 스크립트."
    )
    parser.add_argument(
        "--base-dir",
        type=str,
        default=None,
        help=(
            "*_ChromiumBrowser_HistoryVisits_*.csv 파일을 찾을 기준 디렉터리. "
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

    # ✅ 여기: 모든 HistoryVisits CSV를 가져온다
    candidates = find_historyvisits_csvs(base_dir)
    if not candidates:
        print("[-] *_ChromiumBrowser_HistoryVisits_*.csv 파일을 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
        return

    # ✅ 모든 파일에 대해 태깅 실행
    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {os.path.abspath(input_path)}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략됨)")

        output_path = tag_historyvisits_csv(input_path, ref_time, output_dir)
        print(f"[+] 태깅 완료. 결과 파일: {output_path}")



if __name__ == "__main__":
    main()
