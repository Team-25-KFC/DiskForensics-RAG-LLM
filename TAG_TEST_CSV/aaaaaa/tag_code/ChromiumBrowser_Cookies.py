# -*- coding: utf-8 -*-
"""
ChromiumBrowser_Cookies CSV 정규화 + 태깅 모듈 (D:~Z: + ccit 스캔 버전)

- D:~Z: 전체를 돌면서 "ccit"가 포함된 경로 안에서
  "*ChromiumBrowser_Cookies*.csv"를 찾는다.
- 파일명 앞 14자리(YYYYMMDDHHMMSS)를 기준 시각(ref_time)으로 사용해
  가장 최신 파일 1개를 선택한다.
- 출력은 "해당 드라이브:\ccit\tagged\<원본파일명>_Tagged.csv"로 저장한다.

출력 스키마:
  type, lastwritetimestemp, descrition, tag
"""

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
    r"""
    예: 20251114143910_ChromiumBrowser_Cookies_....csv
        -> 앞 14자리(20251114143910)만 잘라서 2025-11-14 14:39:10 로 변환
    """
    name = os.path.basename(filename)

    m = re.match(r"(\d{14}).*ChromiumBrowser_Cookies.*\.csv$", name)
    if not m:
        return None

    ts_str = m.group(1)  # 20251114143910
    try:
        return datetime.strptime(ts_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ===============================
# 1. D:~Z: 전체에서 ccit 아래 최신 CSV 찾기
# ===============================

def find_latest_cookie_csv_under_ccit() -> Tuple[Optional[Path], Optional[datetime]]:
    """
    D: ~ Z: 전체를 돌면서:
      - root 경로에 'ccit'가 포함된 경우만 탐색 유지
      - 그 아래에서 '*ChromiumBrowser_Cookies*.csv' 파일들을 찾음
      - 파일명 앞 14자리(YYYYMMDDHHMMSS)를 기준 시각(ref_time)으로 파싱
      - ref_time 기준으로 가장 최신 파일 1개를 선택

    반환:
      (파일경로(Path) 또는 None, 기준시각(datetime) 또는 None)
    """
    candidates: List[Tuple[Path, datetime]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        for root, dirs, files in os.walk(str(drive_root)):
            lower_root = root.lower()
            if "ccit" not in lower_root:
                continue

            for name in files:
                if "ChromiumBrowser_Cookies" not in name:
                    continue
                if not name.lower().endswith(".csv"):
                    continue

                ref_time = parse_ref_time_from_filename(name)
                if ref_time is None:
                    continue

                full_path = Path(root) / name
                candidates.append((full_path, ref_time))

    if not candidates:
        return None, None

    # 기준 시각 내림차순 정렬 → 가장 최신 1개
    candidates.sort(key=lambda x: x[1], reverse=True)
    latest_path, latest_ref_time = candidates[0]
    return latest_path, latest_ref_time


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

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - LastAccessUTC는 lastwritetimestemp에 이미 쓰므로 제외
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
# 7. ChromiumBrowser_Cookies CSV → 4컬럼 변환
# ===============================

def tag_cookie_csv(input_path: Path,
                   ref_time: Optional[datetime],
                   output_dir: Path) -> Path:
    """
    - input_path: ChromiumBrowser_Cookies CSV 전체 경로
    - ref_time: 파일명에서 뽑은 기준 시각
    - output_dir: 결과 CSV 저장 디렉터리

    출력 스키마(공통):
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

        # 네가 정한 공통 4컬럼
        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            # type: 아티팩트 종류
            type_val = "ARTIFACT_BROWSER_COOKIE"

            # lastwritetimestemp: LastAccessUTC 그대로 사용
            last_write_ts = (row.get("LastAccessUTC") or "").strip()

            # descrition: 나머지 컬럼 Key:Value | ... 로 합치기
            description = build_description(row)

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
# 8. 메인/엔트리 (D:~Z: + ccit 스캔)
# ===============================

def main():
    print("[ChromiumCookies] D:~Z: + ccit 경로에서 ChromiumBrowser_Cookies CSV 탐색 중...")

    input_path, ref_time = find_latest_cookie_csv_under_ccit()
    if not input_path or not ref_time:
        print("[ChromiumCookies] ChromiumBrowser_Cookies CSV를 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
        return

    print(f"[ChromiumCookies] 선택된 입력 파일: {input_path}")
    print(f"[ChromiumCookies] 파일명 기준 기준 시각(ref_time): {ref_time}")

    # ccit 루트 찾고, 그 아래 tagged 폴더로 출력
    ccit_root = find_ccit_root(input_path)
    output_dir = ccit_root / "tagged"

    print(f"[ChromiumCookies] 출력 디렉터리: {output_dir}")

    output_path = tag_cookie_csv(input_path, ref_time, output_dir)
    print(f"[ChromiumCookies] 태깅/변환 완료. 결과 파일: {output_path}")


# 오케스트레이터에서 호출할 수 있게 run도 정의
def run(*args, **kwargs):
    """
    오케스트레이터에서 run(drive_letters, cfg) 형태로 호출해도 되고,
    단독 실행 시에도 main()만 쓰면 된다.
    여기서는 D:~Z: + ccit 스캔만 사용하므로 args/cfg는 무시한다.
    """
    main()


if __name__ == "__main__":
    main()
