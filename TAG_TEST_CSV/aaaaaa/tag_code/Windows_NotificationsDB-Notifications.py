# -*- coding: utf-8 -*-
"""
Windows_NotificationsDB-Notifications CSV 태깅 스크립트 (Payload hex 디코딩 포함)

✔ 입력:
    D:~Z: 전체를 재귀 탐색하면서
    경로에 'ccit' 가 포함된 폴더 아래의
    *Windows_NotificationsDB-Notifications*.csv (KAPE SQLECmd 출력)

✔ 출력:
    각 드라이브의 ccit\tagged 폴더에
    type, lastwritetimestemp, descrition, tag 4컬럼 구조 CSV 생성

    - type               : "Windows_NotificationsDB-Notifications" 고정
    - lastwritetimestemp : ArrivalTime 원본 문자열
    - descrition         : (Payload hex → 텍스트 포함) Key:Value | ... 형식
    - tag                : 쉼표(,)로 연결한 태그 문자열

태그 정책:
- 기본 태그:
    - ARTIFACT_DB
    - AREA_APPDATA_LOCAL
    - ACT_COMMUNICATION
    - ACT_NOTIFICATION
    - EVENT_CREATE
    - STATE_ACTIVE
- 시간 태그:
    - ArrivalTime 이 유효하면:
        - TIME_CREATED
        - + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나
          (ref_time = 파일명 앞 14자리 기준, 30일 초과면 TIME_OLD)
"""

import os
import csv
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from pathlib import Path

# ------------------------------------------------------
# 0. 공통: 문자열 → datetime 파서
# ------------------------------------------------------

def parse_utc_time(s: str) -> Optional[datetime]:
    """
    '2025-10-13 5:46' 같은 문자열을 datetime으로 변환.
    - 빈 값, 'Expired' 등은 None 처리
    - '1601-01-01 00:00:00' 같은 기본값도 None 처리
    """
    if s is None:
        return None

    s = s.strip()
    if not s:
        return None

    # 의미 없는 기본값(크롬/윈도우 초기값) 버리기
    if s.startswith("1601-01-01"):
        return None

    # 'Expired' 같은 문자만 있는 값은 버리기
    if not any(ch.isdigit() for ch in s):
        return None

    # 'T' → 공백
    s = s.replace("T", " ")

    candidates = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H",
    ]

    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    # ISO 8601 fallback
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def get_time_window_tags(event_dt: Optional[datetime],
                         ref_time: Optional[datetime]) -> List[str]:
    """
    ref_time - event_dt 차이를 보고
    TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나만 돌려준다.
    - 1일 이내: TIME_RECENT
    - 7일 이내: TIME_WEEK
    - 30일 이내: TIME_MONTH
    - 30일 초과: TIME_OLD
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
    else:
        return ["TIME_OLD"]


# ------------------------------------------------------
# 1. 파일명에서 ref_time(기준 시각) 추출
# ------------------------------------------------------

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    if len(filename) < 14:
        return None

    prefix = filename[:14]
    if not prefix.isdigit():
        return None

    try:
        return datetime.strptime(prefix, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ------------------------------------------------------
# 2. D:~Z: 전체에서 ccit 아래 Notifications CSV 찾기
# ------------------------------------------------------

def find_notifications_csvs_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 전체를 재귀적으로 돌면서
    '*Windows_NotificationsDB-Notifications*.csv' 패턴을 모두 찾고,
    (파일 Path, 파일명 기준 ref_time) 리스트를 돌려준다.

    단, 경로에 'ccit' 가 들어간 경우만 대상.
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
                if "Windows_NotificationsDB-Notifications" not in name:
                    continue
                if not name.lower().endswith(".csv"):
                    continue

                full_path = Path(root) / name
                ref_time = parse_ref_time_from_filename(name)

                if ref_time is None:
                    print(f"[DEBUG] Notifications 후보 파일이지만 날짜 파싱 실패: {name}")
                else:
                    print(f"[DEBUG] Notifications 후보 파일: {name}, ref_time={ref_time}")

                results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] Notifications 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] Notifications 후보 파일 개수: {len(results)}")

    return results


# ------------------------------------------------------
# 3. Payload hex → 텍스트 디코딩
# ------------------------------------------------------

def decode_payload_hex(payload: str) -> str:
    """
    Notifications의 Payload 컬럼(16진수 문자열)을 사람이 읽을 수 있는 텍스트로 디코딩.
    - '0x' 프리픽스 제거
    - hex 이외 문자 제거
    - UTF-8 / UTF-16-LE / UTF-16 / CP1252 순서로 디코딩 시도
    - 너무 길면 앞부분만 사용 (예: 400자 정도)
    """
    if not payload:
        return ""

    s = payload.strip()
    if not s:
        return ""

    # 0x 프리픽스 제거
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]

    # hex 이외 문자 제거 (안전하게)
    hex_chars = "0123456789abcdefABCDEF"
    s = "".join(ch for ch in s if ch in hex_chars)

    # 최소 길이 체크
    if len(s) < 4:
        return ""

    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return ""

    for enc in ("utf-8", "utf-16-le", "utf-16", "cp1252"):
        try:
            txt = raw.decode(enc, errors="ignore")
            # 공백 정리 (줄바꿈/탭 등은 공백 하나로)
            txt = " ".join(txt.split())
            # 너무 길면 앞부분만 사용
            if len(txt) > 400:
                txt = txt[:400] + "..."
            return txt
        except UnicodeDecodeError:
            continue

    return ""


# ------------------------------------------------------
# 4. Description 빌더
# ------------------------------------------------------

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - ID, Order, HandlerId, SourceFile 은 Description에서 제외
      - Payload 는 hex → 텍스트로 디코딩 후 "PayloadDecoded:..." 로 저장
      - 나머지는 "Key:Value" 형식으로 이어붙임
    """
    exclude_keys = {
        "ID",
        "Order",
        "HandlerId",
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

        # Payload는 따로 처리 (hex → 텍스트)
        if key == "Payload":
            decoded = decode_payload_hex(s)
            if decoded:
                parts.append(f"PayloadDecoded:{decoded}")
            else:
                # 혹시 디코딩 실패하면 짧게만 남기기
                parts.append(f"PayloadHex:{s[:80]}...")
            continue

        parts.append(f"{key}:{s}")

    return " | ".join(parts)


# ------------------------------------------------------
# 5. output 파일명 충돌 방지 (Path 버전)
# ------------------------------------------------------

def ensure_unique_output_path(path: Path) -> Path:
    if not path.exists():
        return path

    base, ext = os.path.splitext(str(path))
    idx = 1
    while True:
        candidate = Path(f"{base}_v{idx}{ext}")
        if not candidate.exists():
            return candidate
        idx += 1


# ------------------------------------------------------
# 6. ccit 루트 찾기 (출력용)
# ------------------------------------------------------

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


# ------------------------------------------------------
# 7. Notifications CSV 1개 태깅
#    -> (type, lastwritetimestemp, descrition, tag)
# ------------------------------------------------------

def tag_notifications_csv(input_path: Path,
                          ref_time: Optional[datetime],
                          output_dir: Path) -> Path:
    """
    Windows_NotificationsDB-Notifications CSV 한 개를 읽어서
    type, lastwritetimestemp, descrition, tag 4컬럼 구조로 변환해 저장.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)
    output_filename = f"{base_no_ext}_Tagged.csv"
    output_path = ensure_unique_output_path(output_dir / output_filename)

    with input_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         output_path.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)

        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            tags: List[str] = []

            # 기본 태그
            tags.append("ARTIFACT_DB")
            tags.append("AREA_APPDATA_LOCAL")
            tags.append("ACT_COMMUNICATION")
            tags.append("ACT_NOTIFICATION")
            tags.append("EVENT_CREATE")
            tags.append("STATE_ACTIVE")

            # ArrivalTime 기반 시간 태그
            raw_arrival = row.get("ArrivalTime", "") or row.get("Arrival Time", "")
            arrival_dt = parse_utc_time(raw_arrival)
            last_write_ts = raw_arrival.strip() if raw_arrival else ""

            if arrival_dt:
                tags.append("TIME_CREATED")
                tags.extend(get_time_window_tags(arrival_dt, ref_time))

            # Description 생성 (Payload 디코딩 포함)
            description = build_description(row)

            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            writer.writerow({
                "type": "Windows_NotificationsDB-Notifications",
                "lastwritetimestemp": last_write_ts,
                "descrition": description,
                "tag": tag_str,
            })

    return output_path


# ------------------------------------------------------
# 8. main (D:~Z: + ccit 스캔)
# ------------------------------------------------------

def main():
    print("[Notifications] D:~Z: + ccit 경로에서 *Windows_NotificationsDB-Notifications*.csv 탐색 중...")

    candidates = find_notifications_csvs_under_ccit()
    if not candidates:
        print("[-] Windows_NotificationsDB-Notifications CSV를 찾지 못했습니다.")
        return

    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {input_path}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략됨)")

        ccit_root = find_ccit_root(input_path)
        output_dir = ccit_root / "tagged"
        print(f"    -> 출력 디렉터리: {output_dir}")

        out_path = tag_notifications_csv(input_path, ref_time, output_dir)
        print(f"    -> 태깅 완료. 결과 파일: {out_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(...) 형태로 호출해도 되도록 래핑.
    (인자는 무시하고 D:~Z: + ccit 스캔만 수행)
    """
    main()


if __name__ == "__main__":
    main()
