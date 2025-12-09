# -*- coding: utf-8 -*-
import os
import csv
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from pathlib import Path

# =========================================
# 0. 공통: 파일명에서 기준 시각(ref_time) 추출
#    예: 20251114143925168371_Windows_WindowsUpdateStoreDB_....csv
#         -> 2025-11-14 14:39:25
# =========================================

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    """
    파일명 맨 앞 14자리를 YYYYMMDDHHMMSS 형식으로 보고 파싱.
    예: 20251114143925168371_Windows_WindowsUpdateStoreDB_....csv
         -> "20251114143925" 를 기준 시각으로 사용.
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
# 1. D:~Z: 전체에서 ccit 아래 WindowsUpdateStoreDB CSV 찾기
# =========================================

def find_update_store_csvs_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    D:~Z: 전체를 재귀적으로 돌면서
    '*_Windows_WindowsUpdateStoreDB_*.csv' 패턴을 모두 찾고,
    각 파일 Path와 파일명 기준 시각(ref_time)을 리스트로 돌려준다.

    단, 경로에 'ccit' 가 들어간 경우만 대상.
    """
    results: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        for root, dirs, files in os.walk(str(drive_root)):
            # ccit 폴더 아래만 본다
            if "ccit" not in root.lower():
                continue

            for name in files:
                # 파일명 패턴 필터
                if "Windows_WindowsUpdateStoreDB_" not in name:
                    continue
                if not name.lower().endswith(".csv"):
                    continue

                full_path = Path(root) / name
                ref_time = parse_ref_time_from_filename(name)

                if ref_time is None:
                    print(f"[DEBUG] UpdateStoreDB 후보지만 날짜 파싱 실패: {name}")
                else:
                    print(f"[DEBUG] UpdateStoreDB 후보: {name}, ref_time={ref_time}")

                results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] UpdateStoreDB 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] UpdateStoreDB 후보 파일 개수: {len(results)}")

    return results


# =========================================
# 2. Time 파싱 & TIME 태그 계산
# =========================================

def parse_time_str(dt_str: str) -> Optional[datetime]:
    """
    'YYYY-MM-DD HH:MM:SS' 또는 'YYYY-MM-DD HH:MM' 같은 문자열을 datetime으로 변환.
    공백/빈 값은 None.
    """
    if not dt_str:
        return None

    s = dt_str.strip()
    if not s:
        return None

    s = s.replace("T", " ")

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def get_time_tags(mod_dt: Optional[datetime],
                  ref_time: Optional[datetime]) -> List[str]:
    """
    - mod_dt(Time)이 존재하면: TIME_MODIFIED
    - ref_time 과 mod_dt 차이 절댓값 기준으로
      TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 추가
    """
    tags: List[str] = []

    if not mod_dt:
        return tags

    # 기본 태그
    tags.append("TIME_MODIFIED")

    if not ref_time:
        return tags

    diff = ref_time - mod_dt
    days = abs(diff.total_seconds()) / 86400.0

    if days <= 1:
        tags.append("TIME_RECENT")
    elif days <= 7:
        tags.append("TIME_WEEK")
    elif days <= 30:
        tags.append("TIME_MONTH")
    elif days > 30:
        tags.append("TIME_OLD")

    return tags


# =========================================
# 3. Description 빌더
# =========================================

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - Time, SourceFile 은 description에서 제외
      - 나머지를 "Key:Value" 형태로 이어붙여 Description 생성
    구분자: " | "
    """
    exclude_keys = {"Time", "SourceFile"}

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
# 4. output 파일명 충돌 처리 (Path 버전)
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
# 5. ccit 루트 찾기 (출력용)
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
# 6. UpdateStoreDB CSV 태깅
#    -> (type, lastwritetimestemp, descrition, tag)
# =========================================

def tag_updatestore_csv(input_path: Path,
                        ref_time: Optional[datetime],
                        output_dir: Path) -> Path:
    """
    Windows_WindowsUpdateStoreDB CSV 한 개를 태깅해서

    type, lastwritetimestemp, descrition, tag

    4컬럼 형태로 변환해서 저장한다.
    - type              : "Windows_WindowsUpdateStoreDB" 고정
    - lastwritetimestemp: Time 컬럼 문자열 그대로 사용
    - descrition        : Time/SourceFile 컬럼 제외하고
                          "Key:Value | Key2:Value2 ..." 형식으로 합침
    - tag:
        ARTIFACT_DB
        AREA_PROGRAMDATA
        EVENT_MODIFY
        STATE_ACTIVE
        + ACT_INSTALL / ACT_UNINSTALL (조건)
        + TIME_MODIFIED
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

        # 오케스트레이터 규격: 소문자 4컬럼
        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            tags: List[str] = []

            # ---- 기본 태그 ----
            tags.append("ARTIFACT_DB")
            tags.append("AREA_PROGRAMDATA")
            tags.append("EVENT_MODIFY")
            tags.append("STATE_ACTIVE")

            # ---- 설치 / 제거 판별 ----
            history_cat = (row.get("HistoryCategory") or "").strip().lower()
            uninstall_flag = (row.get("Uninstall") or "").strip()

            if "uninstall" in history_cat or uninstall_flag == "1":
                tags.append("ACT_UNINSTALL")
            else:
                tags.append("ACT_INSTALL")

            # ---- 시간 처리 ----
            raw_time = row.get("Time", "")
            mod_dt = parse_time_str(raw_time)
            last_write_ts = raw_time.strip() if raw_time else ""

            tags.extend(get_time_tags(mod_dt, ref_time))

            # ---- Description ----
            description = build_description(row)

            # ---- 태그 정리 ----
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            out_row = {
                "type": "Windows_WindowsUpdateStoreDB",
                "lastwritetimestemp": last_write_ts,
                "descrition": description,
                "tag": tag_str,
            }
            writer.writerow(out_row)

    return output_path


# =========================================
# 7. main (D:~Z: + ccit 스캔)
# =========================================

def main():
    print("[WindowsUpdateStoreDB] D:~Z: + ccit 경로에서 '*_Windows_WindowsUpdateStoreDB_*.csv' 탐색 중...")

    candidates = find_update_store_csvs_under_ccit()
    if not candidates:
        print("[-] *_Windows_WindowsUpdateStoreDB_*.csv 파일을 찾지 못했거나, 파일명 날짜를 파싱하지 못했습니다.")
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

        output_path = tag_updatestore_csv(input_path, ref_time, output_dir)
        print(f"[+] 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(...) 형태로 호출해도 되도록 래핑.
    (인자는 무시하고 D:~Z: + ccit 스캔만 수행)
    """
    main()


if __name__ == "__main__":
    main()
