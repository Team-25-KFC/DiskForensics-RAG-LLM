# -*- coding: utf-8 -*-
import os
import csv
import shutil
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path

# =========================================
# 0. 시간 관련 유틸
# =========================================

def parse_utc_time(s: str) -> Optional[datetime]:
    """
    HistoryVisits의 'LastVisitedTime (UTC)' 같은 문자열을 datetime으로 변환.
    - 빈 값이면 None
    - 1601-01-01 00:00:00 같은 초기값(Null 의미)도 None 처리
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
    else:
        return ["TIME_OLD"]


# =========================================
# 1. Kape Output 아래 HistoryVisits CSV 찾기
# =========================================

def find_kape_historyvisits_csvs() -> List[Path]:
    """
    D:~Z: 전체를 돌면서
    '드라이브 루트\\Kape Output' 아래에서
    '*ChromiumBrowser_HistoryVisits*.csv' 파일을 모두 찾는다.
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
                if "chromiumbrowser_historyvisits" not in lower:
                    continue
                if not lower.endswith(".csv"):
                    continue

                full_path = Path(root) / name
                results.append(full_path)
                print(f"[DEBUG] KAPE HistoryVisits CSV 발견: {full_path}")

    if not results:
        print("[-] 'Kape Output' 아래에서 ChromiumBrowser_HistoryVisits CSV를 찾지 못했습니다.")

    return results


def derive_ref_time_for_csv(csv_path: Path) -> Optional[datetime]:
    """
    CSV 안에서 가장 먼저 나오는 유효한 LastVisitedTime(UTC) / LastVisitedTime 을 ref_time으로 사용.
    없으면 None.
    """
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = (
                    row.get("LastVisitedTime (UTC)", "")
                    or row.get("LastVisitedTime", "")
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
      - ID, VisitID, FromVisitID, LastVisitedTime (UTC), LastVisitedTime 은 description에서 제외
      - 나머지를 "Key:Value" 형태로 이어붙여 descrition 생성
      - extra 딕셔너리는 추가 메타데이터(CsvPath 등)를 붙이는 용도
    """
    exclude_keys = {
        "ID",
        "VisitID",
        "FromVisitID",
        "LastVisitedTime (UTC)",
        "LastVisitedTime",
    }

    parts: List[str] = []

    # 원래 CSV 컬럼
    for key, val in row.items():
        if key in exclude_keys:
            continue
        if val is None:
            continue
        s = str(val).strip()
        if not s:
            continue
        parts.append(f"{key}:{s}")

    # 추가 메타데이터
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
# 6. 브라우저 이벤트 판별(다운로드/폼 제출)
# =========================================

def _detect_browser_download(url: str) -> bool:
    """
    URL만 보고 '다운로드 이벤트일 가능성'을 대충 판별.
    EVENT_BROWSER_DOWNLOAD 태그 용도.
    """
    if not url:
        return False

    u = url.lower()

    # file:// 로 시작하면 로컬 파일 열기 (다운로드 산물일 가능성)
    if u.startswith("file://"):
        return True

    # download, attachment 같은 흔한 패턴
    if "/download" in u or "download=" in u or "attachment=" in u:
        return True

    # 확장자 기반 (대략적인 규칙)
    download_exts = [
        ".exe", ".msi", ".zip", ".rar", ".7z",
        ".iso", ".img",
        ".pdf",
        ".doc", ".docx",
        ".xls", ".xlsx",
        ".ppt", ".pptx",
    ]

    main_part = u.split("?", 1)[0]
    for ext in download_exts:
        if main_part.endswith(ext):
            return True

    return False


def _detect_form_submit(row: Dict[str, str]) -> bool:
    """
    HistoryVisits에서 폼 제출/검색으로 보이는지 대략 판별.
    Transition/TransitionType 컬럼 안에 form/submit 같은 단어가 있으면 TRUE.
    """
    trans = (
        row.get("Transition", "")
        or row.get("TransitionType", "")
        or row.get("Transition Type", "")
    )
    if not trans:
        return False

    t = str(trans).lower()
    if "form" in t or "submit" in t:
        return True

    return False


# =========================================
# 7. HistoryVisits CSV 태깅
#    -> (type / lastwritetimestemp / descrition / tag)
# =========================================

def tag_historyvisits_csv(input_path: Path,
                          ref_time: Optional[datetime],
                          output_dir: Path,
                          kape_child: Optional[str] = None) -> Path:
    """
    ChromiumBrowser_HistoryVisits CSV 한 개를 태깅해서

      type, lastwritetimestemp, descrition, tag

    4컬럼 형태로 변환해서 저장한다.

    - type: "ARTIFACT_BROWSER_HISTORY" 고정
    - lastwritetimestemp: 'LastVisitedTime (UTC)' 또는 'LastVisitedTime' 문자열 그대로
    - descrition: ID/VisitID/FromVisitID/LastVisitedTime 계열 제외 + CsvPath/CsvName 메타
    - tag:
        ARTIFACT_BROWSER_HISTORY
        AREA_APPDATA_LOCAL
        ACT_BROWSING
        EVENT_BROWSER_VISIT
        EVENT_ACCESSED
        STATE_ACTIVE
        (+ EVENT_BROWSER_DOWNLOAD : 다운로드로 추정되면)
        (+ EVENT_BROWSER_FORM_SUBMIT : 폼 제출/검색으로 추정되면)
        (+ TIME_ACCESSED : LastVisitedTime 유효)
        (+ TIME_RECENT / TIME_WEEK / TIME_MONTH / TIME_OLD 중 하나 : ref_time 기준)
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

        # 최종 출력 컬럼 4개 (공통 스키마)
        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        # 공통 메타데이터(어디서 온 CSV인지)
        extra_common = {
            "CsvPath": str(input_path),
            "CsvName": input_basename,
        }

        for row in reader:
            tags: List[str] = []

            # --- 기본 태그 ---
            tags.append("ARTIFACT_BROWSER_HISTORY")
            tags.append("AREA_APPDATA_LOCAL")
            tags.append("ACT_BROWSING")
            tags.append("EVENT_BROWSER_VISIT")
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
            last_write_ts = raw_last_visited.strip() if raw_last_visited else ""

            if last_visited_dt:
                tags.append("TIME_ACCESSED")
                tags.extend(get_time_window_tags(last_visited_dt, ref_time))

            # ===========================
            # ② 브라우저 이벤트 태그(다운로드/폼 제출)
            # ===========================
            url_val = (
                row.get("URL", "")
                or row.get("Url", "")
                or row.get("url", "")
            )

            # 다운로드로 추정
            if _detect_browser_download(url_val):
                tags.append("EVENT_BROWSER_DOWNLOAD")

            # 폼 제출/검색으로 추정
            if _detect_form_submit(row):
                tags.append("EVENT_BROWSER_FORM_SUBMIT")

            # ===========================
            # ③ descrition 빌드
            # ===========================
            description = build_description(row, extra=extra_common)

            # ===========================
            # ④ 태그 정리 & 최종 레코드 작성
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
# 8. main (Kape Output 스캔 → artifact_csv 복사 → tagged 출력)
# =========================================

def main():
    print("[HistoryVisits] D:~Z: 의 'Kape Output' 아래에서 ChromiumBrowser_HistoryVisits CSV 탐색 중...")

    kape_csvs = find_kape_historyvisits_csvs()
    if not kape_csvs:
        return

    # 1단계: KAPE CSV → ccit\artifact_csv 로 복사 + ref_time 계산
    copied_list: List[Tuple[Path, datetime, str]] = []

    for src_path in kape_csvs:
        print(f"[+] 원본 KAPE CSV: {src_path}")

        # ref_time: CSV 내부에서 가장 먼저 나오는 방문 시간
        ref_time = derive_ref_time_for_csv(src_path)
        if ref_time:
            print(f"    -> ref_time(첫 방문 시각 기준): {ref_time}")
        else:
            # 없으면 파일 mtime 사용
            ref_time = datetime.fromtimestamp(src_path.stat().st_mtime)
            print(f"    -> ref_time 없음, 파일 mtime 사용: {ref_time}")

        # Kape Output 바로 아래 폴더명 (예: G, H ...)
        kape_child = get_kape_child_name(src_path)
        print(f"    -> Kape 하위 폴더 라벨: {kape_child}")

        # ccit 루트 찾기 (예: D:\ccit)
        ccit_root = find_ccit_root(src_path)

        # artifact_csv 디렉터리 (예: D:\ccit\artifact_csv)
        artifact_dir = ccit_root / "artifact_csv"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        # ref_time 기반 prefix를 붙여서 복사
        prefix = ref_time.strftime("%Y%m%d%H%M%S")
        new_name = f"{prefix}_{src_path.name}"
        dest_path = ensure_unique_output_path(artifact_dir / new_name)

        shutil.copy2(src_path, dest_path)
        print(f"    -> artifact_csv 복사/이름변경: {dest_path}")

        copied_list.append((dest_path, ref_time, kape_child))

    # 2단계: artifact_csv → tagged (ccit와 같은 레벨의 tagged 폴더)
    for artifact_path, ref_time, kape_child in copied_list:
        ccit_root = find_ccit_root(artifact_path)
        # ccit와 같은 경로에 tagged 생성 (예: D:\ccit -> D:\tagged)
        output_dir = ccit_root.parent / "tagged"

        print(f"[TAG] 입력 파일: {artifact_path}")
        print(f"      출력 디렉터리: {output_dir}")

        output_path = tag_historyvisits_csv(
            artifact_path,
            ref_time,
            output_dir,
            kape_child=kape_child
        )
        print(f"      -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(...) 형태로 호출해도 되고,
    단독 실행 시에는 main()만 써도 된다.
    """
    main()


if __name__ == "__main__":
    main()
