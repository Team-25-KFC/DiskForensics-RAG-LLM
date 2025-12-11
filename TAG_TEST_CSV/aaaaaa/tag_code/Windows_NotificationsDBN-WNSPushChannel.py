# -*- coding: utf-8 -*-
"""
Windows_NotificationsDBN-WNSPushChannel CSV 태깅 스크립트

✔ 입력:
    D:~Z: 각 드라이브 루트의
    "Kape Output" 폴더 아래를 재귀 탐색하면서
    *_Windows_NotificationsDBN-WNSPushChannel_*.csv (KAPE SQLECmd 출력) 찾기

✔ 출력:
    각 드라이브의 "tagged" 폴더에
    type, lastwritetimestemp, descrition, tag 4컬럼 구조 CSV 생성

    - type               : "Windows_NotificationsDBN-WNSPushChannel" 고정
    - lastwritetimestemp : CreatedTime 원본 문자열
    - descrition         : SourceFile 제외, Key:Value | ... 형식
    - tag                : 쉼표(,)로 연결한 태그 문자열

✔ 파일 이름 규칙:
    입력 경로가
        <드라이브>:\Kape Output\<CASE>\...\원본.csv
    인 경우,
        <드라이브>:\tagged\원본파일명_<CASE>_Tagged.csv
    형식으로 저장.
"""

import os
import csv
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from pathlib import Path

# =========================================
# 0. 공통 시간 파싱 & TIME 윈도 태그
# =========================================

def parse_utc_time(s: str) -> Optional[datetime]:
    """
    NotificationsDBN-WNSPushChannel의 CreatedTime/ExpirationTime 같은 문자열을 datetime으로 변환.
    - 빈 값이면 None
    - 몇 가지 대표 형식을 순차적으로 시도
    """
    if s is None:
        return None

    s = s.strip()
    if not s:
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
    else:
        return ["TIME_OLD"]


def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    파일명 맨 앞 14자리가 YYYYMMDDHHMMSS 형식이라고 가정하고 파싱.
    예: 20251114143925_Windows_NotificationsDBN-WNSPushChannel_....csv
         -> "20251114143925"만 잘라서 기준 시각으로 사용.
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
# 1. D:~Z: 전체에서 Kape Output 아래 Notifications CSV 찾기
# =========================================

def find_notifications_csvs_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 각 드라이브에 대해

    - 루트 경로에 "Kape Output" 폴더가 있는지 확인
      예) D:\\Kape Output, E:\\Kape Output
    - 해당 "Kape Output" 폴더 아래를 재귀적으로 돌면서
      '*_Windows_NotificationsDBN-WNSPushChannel_*.csv' 패턴을 모두 찾는다.

    찾은 각 파일에 대해 (Path, 파일명 기준 시각(ref_time)) 튜플을 반환.
    """
    results: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = drive_root / "Kape Output"
        if not kape_root.is_dir():
            continue

        print(f"[DEBUG] 드라이브 {drive_root} 에서 Kape Output 경로 탐색: {kape_root}")

        for root, dirs, files in os.walk(str(kape_root)):
            for name in files:
                # 파일명 패턴 필터
                if "_Windows_NotificationsDBN-WNSPushChannel_" not in name:
                    continue
                if not name.lower().endswith(".csv"):
                    continue

                full_path = Path(root) / name
                ref_time = parse_ref_time_from_filename(name)

                if ref_time is None:
                    print(f"[DEBUG] WNSPushChannel 후보 파일이지만 날짜 파싱 실패: {full_path}")
                else:
                    print(f"[DEBUG] WNSPushChannel 후보 파일: {full_path}, ref_time={ref_time}")

                results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] WNSPushChannel 후보 파일 리스트가 비어 있음 (Kape Output 경로/필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] WNSPushChannel 후보 파일 개수: {len(results)}")

    return results


# =========================================
# 2. description 빌더 (SourceFile 제외)
# =========================================

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - SourceFile 컬럼은 description에서 제외
      - 나머지를 "Key:Value" 형태로 이어붙여 Description 생성
    구분자: " | "
    """
    exclude_keys = {
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
# 3. output 파일명 충돌 처리 (Path 버전)
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
# 4. ccit 루트 찾기 (출력용 기준)
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
# 4-1. Kape Output 하위 폴더 이름 추출
#      (Kape Output 바로 아래 1단계 폴더명만)
# =========================================

def get_kape_child_folder_name(input_path: Path) -> Optional[str]:
    """
    input_path 가
        <드라이브>:\Kape Output\<CASE>\...\file.csv
    형태라고 가정하고,

    - 'Kape Output' 폴더를 위로 올라가며 찾은 뒤
    - 그 기준 상대 경로의 첫 번째 부분(하위 폴더 이름, 예: 'Jo', 'Terry') 하나만 반환.

    못 찾으면 None.
    """
    for parent in [input_path] + list(input_path.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = input_path.relative_to(parent)
            except ValueError:
                return None

            # 예: rel.parts = ('Jo', 'SQLECmd', '...', 'file.csv')
            if rel.parts:
                return rel.parts[0]
            return None

    return None


# =========================================
# 5. Notifications CSV 태깅
#    -> (type, lastwritetimestemp, descrition, tag)
# =========================================

def tag_notifications_csv(input_path: Path,
                          ref_time: Optional[datetime],
                          output_dir: Path,
                          kape_child_name: Optional[str] = None) -> Path:
    """
    Windows_NotificationsDBN-WNSPushChannel CSV 한 개를 태깅해서

    type, lastwritetimestemp, descrition, tag

    4컬럼 형태로 변환해서 저장한다.
    - type              : "Windows_NotificationsDBN-WNSPushChannel" 고정
    - lastwritetimestemp: CreatedTime 컬럼 문자열
    - descrition        : SourceFile 컬럼 제외하고
                          "Key:Value | Key2:Value2 ..." 형식으로 합침
    - tag:
        ARTIFACT_DB
        AREA_APPDATA_LOCAL
        ACT_COMMUNICATION
        EVENT_CREATE
        STATE_ACTIVE
        + TIME_CREATED (CreatedTime가 유효할 때)
        + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 (ref_time 기준)

    output_dir 는 'tagged' 경로를 넘겨준다.
    파일 이름은 원본 파일명 + Kape Output 하위폴더명을 반영해 생성한다.
    예) 2025..._Windows_NotificationsDBN-WNSPushChannel_..._Jo_Tagged.csv
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)

    # Kape Output 하위 폴더 이름이 있으면 파일명에 포함
    if kape_child_name:
        output_filename = f"{base_no_ext}_{kape_child_name}_Tagged.csv"
    else:
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

            # --- 기본 태그 ---
            tags.append("ARTIFACT_DB")
            tags.append("AREA_APPDATA_LOCAL")
            tags.append("ACT_COMMUNICATION")
            tags.append("EVENT_CREATE")
            tags.append("STATE_ACTIVE")

            # ===========================
            # ① CreatedTime 기반 시간 태그
            # ===========================
            raw_created = row.get("CreatedTime", "") or row.get("Created Time", "")
            created_dt = parse_utc_time(raw_created)

            # lastwritetimestemp 컬럼에 들어갈 문자열
            last_write_ts = raw_created.strip() if raw_created else ""

            if created_dt:
                tags.append("TIME_CREATED")
                tags.extend(get_time_window_tags(created_dt, ref_time))

            # ===========================
            # ② Description 빌드 (SourceFile 제외)
            # ===========================
            description = build_description(row)

            # ===========================
            # ③ 태그 정리 & 최종 레코드
            # ===========================
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            output_row = {
                "type": "Windows_NotificationsDBN-WNSPushChannel",
                "lastwritetimestemp": last_write_ts,
                "descrition": description,
                "tag": tag_str,
            }
            writer.writerow(output_row)

    return output_path


# =========================================
# 6. main (D:~Z: + Kape Output 스캔)
# =========================================

def main():
    print("[WNSPushChannel] D:~Z: 드라이브의 'Kape Output' 경로에서 *_Windows_NotificationsDBN-WNSPushChannel_*.csv 탐색 중...")

    candidates = find_notifications_csvs_under_ccit()
    if not candidates:
        print("[-] *_Windows_NotificationsDBN-WNSPushChannel_*.csv 파일을 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
        return

    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {input_path}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략됨)")

        # ccit 기준 루트 찾기
        ccit_root = find_ccit_root(input_path)

        # 출력 디렉터리: ccit 폴더와 같은 레벨의 'tagged'
        # 예) D:\ccit -> D:\tagged
        base_dir = ccit_root.parent
        output_dir = base_dir / "tagged"

        # Kape Output 하위 폴더 이름 (예: Jo, Terry)
        kape_child = get_kape_child_folder_name(input_path)
        if kape_child:
            print(f"    -> Kape Output 하위 폴더 이름: {kape_child}")
        else:
            print("    -> Kape Output 하위 폴더 이름을 찾지 못함 (파일명에 CASE 미포함일 수 있음)")

        print(f"    -> 출력 디렉터리: {output_dir}")

        output_path = tag_notifications_csv(input_path, ref_time, output_dir, kape_child)
        print(f"[+] 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(...) 형태로 호출해도 되도록 래핑.
    (인자는 무시하고 D:~Z: + Kape Output 스캔만 수행)
    """
    main()


if __name__ == "__main__":
    main()
