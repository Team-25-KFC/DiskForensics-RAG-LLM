# -*- coding: utf-8 -*-
import os
import csv
import shutil
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

    return None


def get_time_window_tags(event_dt: Optional[datetime],
                         ref_time: Optional[datetime]) -> List[str]:
    """
    ref_time - event_dt 차이를 보고
    TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나만 돌려준다.
      - ≤ 1일    -> TIME_RECENT
      - ≤ 7일    -> TIME_WEEK
      - ≤ 30일   -> TIME_MONTH
      - 30일 초과 -> TIME_OLD
    """
    if not event_dt or not ref_time:
        return []

    diff = ref_time - event_dt
    days = abs(diff.total_seconds()) / 86400.0

    if days <= 1:
        return ["TIME_RECENT"]
    elif days <= 7:
        return ["TIME_WEEK"]
    elif days <= 30:
        return ["TIME_MONTH"]
    else:
        return ["TIME_OLD"]


# =========================================
# 1. Kape Output 아래에서 KeywordSearches CSV 찾기
# =========================================

def find_kape_keywordsearches_csvs() -> List[Path]:
    """
    D:~Z: 전체를 돌면서
    '드라이브 루트\\Kape Output' 아래에서
    '*ChromiumBrowser_KeywordSearches*.csv' 파일을 찾는다.
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
                if "chromiumbrowser_keywordsearches" not in lower:
                    continue
                if not lower.endswith(".csv"):
                    continue

                full_path = Path(root) / name
                results.append(full_path)
                print(f"[DEBUG] KAPE KeywordSearches CSV 발견: {full_path}")

    if not results:
        print("[-] 'Kape Output' 아래에서 ChromiumBrowser_KeywordSearches CSV를 찾지 못했습니다.")

    return results


def derive_ref_time_for_csv(csv_path: Path) -> Optional[datetime]:
    """
    CSV 안에서 가장 먼저 나오는 유효한 LastVisitTime / LastVisitTime (UTC)를 ref_time으로 사용.
    없으면 None.
    """
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = (
                    row.get("LastVisitTime", "")
                    or row.get("LastVisitTime (UTC)", "")
                )
                if not raw:
                    continue

                dt = parse_utc_time(raw)
                if dt:
                    return dt
        return None
    except Exception as e:
        print(f"[WARN] ref_time 추출 중 오류 발생: {csv_path} -> {e}")
        return None


# =========================================
# 2. Description 빌더
# =========================================

def build_description(row: Dict[str, str],
                      extra: Optional[Dict[str, str]] = None) -> str:
    """
    한 행(row)에서:
      - KeywordID, URLID, LastVisitTime, LastVisitTime (UTC)는 description에서 제외
      - SourceFile 은 포함 (원본 히스토리 DB 경로)
      - extra 로 들어오는 항목(CsvPath, CsvName 등)을 마지막에 추가
      - 최종 형식: "Key:Value | Key2:Value2 | ..."
    """
    exclude_keys = {
        "KeywordID",
        "URLID",
        "LastVisitTime",
        "LastVisitTime (UTC)",
    }

    parts: List[str] = []

    # 원본 CSV 컬럼들
    for key, val in row.items():
        if key in exclude_keys:
            continue
        if val is None:
            continue
        s = str(val).strip()
        if not s:
            continue
        parts.append(f"{key}:{s}")

    # 추가 컨텍스트(CsvPath, CsvName 등)
    if extra:
        for key, val in extra.items():
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
# 4. ccit 루트 찾기 (artifact_csv용)
# =========================================

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


# =========================================
# 5. Kape Output 하위 1단계 폴더명 추출
# =========================================

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


# =========================================
# 6. KeywordSearches CSV 태깅
#    -> (type / lastwritetimestemp / descrition / tag)
# =========================================

def tag_keywordsearches_csv(input_path: Path,
                            ref_time: Optional[datetime],
                            output_dir: Path,
                            kape_child: Optional[str] = None) -> Path:
    """
    ChromiumBrowser_KeywordSearches CSV 한 개를 태깅해서

      type, lastwritetimestemp, descrition, tag

    4컬럼 형태로 변환해서 저장한다.

    - type: "ARTIFACT_BROWSER_HISTORY" 고정
    - lastwritetimestemp: LastVisitTime(또는 LastVisitTime (UTC)) 문자열 사용
    - descrition:
        KeywordID, URLID, LastVisitTime 계열을 제외하고
        SourceFile(히스토리 DB 경로)은 포함
        + 각 행마다 CsvPath, CsvName(정규화 스크립트 입력 CSV 정보)를 추가
    - tag:
        ARTIFACT_BROWSER_HISTORY
        AREA_APPDATA_LOCAL
        ACT_SEARCH
        ACT_BROWSING
        EVENT_BROWSER_FORM_SUBMIT   (검색어 입력/폼 제출)
        EVENT_BROWSER_VISIT         (검색 결과 페이지 방문)
        EVENT_ACCESSED
        STATE_ACTIVE
        + TIME_ACCESSED (LastVisitTime가 유효할 때)
        + TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 (ref_time 기준)
    - output_dir: ccit와 같은 레벨의 tagged 디렉터리 (예: D:\\tagged)
    - kape_child: 'Kape Output' 바로 아래 하위 폴더명 (예: 'G')
                  출력 파일 이름에 prefix로 붙는다.
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
            tags: List[str] = []

            # --- 기본 태그 ---
            tags.append("ARTIFACT_BROWSER_HISTORY")
            tags.append("AREA_APPDATA_LOCAL")
            tags.append("ACT_SEARCH")
            tags.append("ACT_BROWSING")
            tags.append("EVENT_BROWSER_FORM_SUBMIT")
            tags.append("EVENT_BROWSER_VISIT")
            tags.append("EVENT_ACCESSED")
            tags.append("STATE_ACTIVE")

            # ① LastVisitTime 기반 시간 태그
            raw_last_visit = (
                row.get("LastVisitTime", "")
                or row.get("LastVisitTime (UTC)", "")
            )

            last_visit_dt = parse_utc_time(raw_last_visit)
            last_write_ts = raw_last_visit.strip() if raw_last_visit else ""

            if last_visit_dt:
                tags.append("TIME_ACCESSED")
                tags.extend(get_time_window_tags(last_visit_dt, ref_time))

            # ② descrition 생성 (행 데이터 + CsvPath/CsvName)
            description = build_description(row, extra=extra_common)

            # ③ 태그 정리 & 출력
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
# 7. main (Kape Output 스캔 → artifact_csv 복사 → tagged 출력)
# =========================================

def main():
    print("[KeywordSearches] D:~Z: 의 'Kape Output' 아래에서 ChromiumBrowser_KeywordSearches CSV 탐색 중...")

    kape_csvs = find_kape_keywordsearches_csvs()
    if not kape_csvs:
        return

    copied_list: List[Tuple[Path, datetime, str]] = []

    # 1단계: 원본 KAPE CSV → ccit\\artifact_csv 로 복사 + ref_time 계산
    for src_path in kape_csvs:
        print(f"[+] 원본 KAPE CSV: {src_path}")

        ref_time = derive_ref_time_for_csv(src_path)
        if ref_time:
            print(f"    -> ref_time(첫 검색 시각 기준): {ref_time}")
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

        output_path = tag_keywordsearches_csv(
            artifact_path,
            ref_time,
            output_dir,
            kape_child=kape_child,
        )
        print(f"      -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(drive_letters, cfg) 형태로 호출해도 되고,
    단독 실행 시에는 main()만 써도 된다.
    """
    main()


if __name__ == "__main__":
    main()
