# -*- coding: utf-8 -*-
import os
import csv
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path

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
# 1. D:~Z: 전체에서 ccit 아래 KeywordSearches CSV 찾기
# =========================================

def find_keywordsearch_csvs_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 전체를 재귀적으로 돌면서
    '*_ChromiumBrowser_KeywordSearches_*.csv' 패턴을 모두 찾고,
    각 파일 Path와 파일명 기준 시각(ref_time)을 리스트로 돌려준다.

    단, 경로에 'ccit'가 들어간 경우만 대상.
    """
    results: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        for root, dirs, files in os.walk(str(drive_root)):
            lower_root = root.lower()
            if "ccit" not in lower_root:
                continue

            for name in files:
                if "_ChromiumBrowser_KeywordSearches_" not in name:
                    continue
                if not name.lower().endswith(".csv"):
                    continue

                full_path = Path(root) / name
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
      - 나머지를 "Key:Value" 형태로 이어붙여 descrition 생성
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


# =========================================
# 4. ccit 루트 찾기 (출력용)
# =========================================

def find_ccit_root(path: Path) -> Path:
    """
    입력 CSV가 있는 경로에서 위로 올라가면서
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


# =========================================
# 5. KeywordSearches CSV 태깅
#    -> (type / lastwritetimestemp / descrition / tag)
# =========================================

def tag_keywordsearches_csv(input_path: Path,
                            ref_time: Optional[datetime],
                            output_dir: Path) -> Path:
    """
    ChromiumBrowser_KeywordSearches CSV 한 개를 태깅해서

      type, lastwritetimestemp, descrition, tag

    4컬럼 형태로 변환해서 저장한다.
    - type: "ARTIFACT_BROWSER_HISTORY" 고정
    - lastwritetimestemp: LastVisitTime(또는 LastVisitTime (UTC)) 문자열 사용
    - descrition:
        KeywordID, URLID, LastVisitTime 계열, SourceFile 을 제외하고
        "Key:Value | Key2:Value2 ..." 형식으로 합침
    - tag:
        ARTIFACT_BROWSER_HISTORY
        AREA_APPDATA_LOCAL
        ACT_SEARCH
        ACT_BROWSING
        EVENT_ACCESSED
        STATE_ACTIVE
        + TIME_ACCESSED (LastVisitTime가 유효할 때)
        + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 (ref_time 기준)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)
    output_filename = f"{base_no_ext}_Tagged.csv"
    output_path = ensure_unique_output_path(output_dir / output_filename)

    with input_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         output_path.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)

        # 최종 출력 컬럼 4개 (공통 스키마)
        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
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
            # ② descrition 생성
            # ===========================
            description = build_description(row)

            # ===========================
            # ③ 태그 정리 & 출력
            # ===========================
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            output_row = {
                "type": "ARTIFACT_BROWSER_HISTORY",
                "lastwritetimestemp": last_write_ts,
                "descrition": description,
                "tag": tag_str,
            }
            writer.writerow(output_row)

    return output_path


# =========================================
# 6. main (D:~Z: + ccit 스캔)
# =========================================

def main():
    print("[KeywordSearches] D:~Z: + ccit 경로에서 *_ChromiumBrowser_KeywordSearches_*.csv 탐색 중...")

    candidates = find_keywordsearch_csvs_under_ccit()
    if not candidates:
        print("[-] *_ChromiumBrowser_KeywordSearches_*.csv 파일을 찾지 못했습니다.")
        return

    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {input_path}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략될 수 있음)")

        ccit_root = find_ccit_root(input_path)
        output_dir = ccit_root / "tagged"
        print(f"    -> 출력 디렉터리: {output_dir}")

        output_path = tag_keywordsearches_csv(input_path, ref_time, output_dir)
        print(f"    -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(drive_letters, cfg) 형태로 호출해도 되고,
    단독 실행 시에는 main()만 써도 된다.
    여기서는 D:~Z: + ccit 스캔만 사용하므로 args/cfg는 무시한다.
    """
    main()


if __name__ == "__main__":
    main()
