# -*- coding: utf-8 -*-
import os
import re
import csv
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from pathlib import Path

# ===============================
# 0. 파일명에서 기준 시각(ref_time) 추출
# ===============================

def parse_ref_time_from_filename(filename: str) -> Optional[datetime]:
    r"""
    예: 20251126183954_PECmd_Output.csv -> 2025-11-26 18:39:54 로 변환
    """
    m = re.match(r"(\d{14})_PECmd_Output\.csv$", filename)
    if not m:
        return None
    ts_str = m.group(1)
    try:
        return datetime.strptime(ts_str, "%Y%m%d%H%M%S")
    except ValueError:
        return None


# ===============================
# 1. D:~Z: 전체에서 Kape Output 아래 PECmd CSV 찾기
# ===============================

def find_pecmd_csvs_under_ccit() -> List[Tuple[Path, Optional[datetime]]]:
    """
    (이름은 그대로 두지만 동작은 Kape Output 기준으로 변경)

    D:~Z: 전체를 돌면서
    각 드라이브 루트의 'Kape Output' 폴더 아래에서
    '*_PECmd_Output.csv' 패턴을 모두 찾고,
    각 파일 Path와 파일명 기준 시각(ref_time)을 리스트로 돌려준다.
    """
    results: List[Tuple[Path, Optional[datetime]]] = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(drive_code)}:\\")
        if not drive_root.exists():
            continue

        kape_root = drive_root / "Kape Output"
        if not kape_root.exists():
            continue

        print(f"[DEBUG] 드라이브 {drive_root} 의 Kape Output 탐색: {kape_root}")

        for root, dirs, files in os.walk(str(kape_root)):
            for name in files:
                if not name.endswith("_PECmd_Output.csv"):
                    continue

                full_path = Path(root) / name
                ref_time = parse_ref_time_from_filename(name)

                if ref_time is None:
                    print(f"[DEBUG] PECmd 후보 파일이지만 날짜 파싱 실패: {name}")
                else:
                    print(f"[DEBUG] PECmd 후보 파일: {name}, ref_time={ref_time}")

                results.append((full_path, ref_time))

    if not results:
        print("[DEBUG] PECmd 후보 파일 리스트가 비어 있음 (필터/파싱 문제 가능)")
    else:
        print(f"[DEBUG] PECmd 후보 파일 개수: {len(results)}")

    return results


# ===============================
# 1-1. Kape Output 하위 1단계 폴더 이름 추출
# ===============================

def get_kape_child_folder_name(csv_path: Path) -> Optional[str]:
    """
    csv_path 가
        <드라이브>:\Kape Output\<CASE>\...\file.csv
    형태라고 가정하고,

    - 위로 올라가면서 'Kape Output' 폴더를 찾은 다음
    - 그 기준 상대 경로의 첫 번째 부분(하위 폴더 이름, 예: 'Jo', 'Terry')을 반환.

    못 찾으면 None.
    """
    p = csv_path
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None

            # 예: rel.parts = ('Jo', 'SQLECmd', '...', 'file.csv')
            if rel.parts:
                return rel.parts[0]
            return None

    return None


# ===============================
# 2. Directories / FilesLoaded 요약 유틸
# ===============================

def normalize_volume(path: str) -> str:
    r"""
    \VOLUME{GUID}\WINDOWS\SYSTEM32\NTDLL.DLL
      -> C:\WINDOWS\SYSTEM32\NTDLL.DLL 형태로 치환 (일단 C:로 고정)
    """
    path = path.strip()
    if not path:
        return ""
    path = re.sub(r"^\\VOLUME\{[^}]+\}", r"C:", path, flags=re.IGNORECASE)
    return path

def shorten_dir_path(path: str) -> str:
    """
    경로가 너무 길면:
      C:\F1\F2\F3\...\Fn-1\Fn
      -> C:\F1\...\Fn-1\Fn  (드라이브 + 첫 폴더 + ... + 마지막 2개)
    """
    if not path:
        return path
    parts = path.split("\\")
    if len(parts) <= 4:
        return path
    drive = parts[0]
    first = parts[1]
    tail = "\\".join(parts[-2:])
    return f"{drive}\\{first}\\...\\{tail}"

def summarize_files_in_dir(files: List[str]) -> str:
    """
    한 디렉터리 안의 파일 목록을 요약한다.

    - MUM / CAT / MAN 같은 패키지 파일에서 '~' 앞부분을 공통 키로 묶어서
      MICROSOFT-WINDOWS-XXXX-PACKAGE (xN) 형태로 표현
    - 그 외 일반 파일은 그대로 표시
    """
    base_map: Dict[str, List[str]] = {}

    for name in files:
        if not name:
            continue

        upper = name.upper()

        # 패키지 계열: MICROSOFT-...~31BF... 처럼 '~'가 들어가는 애들
        if "~" in name and (upper.endswith(".MUM") or upper.endswith(".CAT") or upper.endswith(".MAN")):
            base = name.split("~", 1)[0]  # 첫 번째 ~ 앞까지를 "패밀리"로 사용
        else:
            base = name  # 그냥 일반 파일

        base_map.setdefault(base, []).append(name)

    summarized_items: List[str] = []

    for base in sorted(base_map.keys()):
        group = base_map[base]
        if len(group) == 1:
            # 한 개만 있으면 원래 파일 이름 그대로
            summarized_items.append(group[0])
        else:
            # 여러 개이면 "공통prefix (xN)" 형식으로
            summarized_items.append(f"{base} (x{len(group)})")

    return ", ".join(summarized_items)


def summarize_files_list(raw_str: str) -> str:
    r"""
    'path1, path2, ...' 형식을
    'DIR1\ (file1, file2, ...); DIR2\ (fileA, ...); ...'
    로 요약.

    - 디렉터리별로 파일을 모은 후
    - 각 디렉터리 안에서는 summarize_files_in_dir() 로 추가 요약
    """
    if not raw_str:
        return ""

    # 1) 경로 정규화
    paths = [normalize_volume(p) for p in raw_str.split(",") if p.strip()]

    # 2) 디렉터리 → 파일 목록 매핑
    dir_to_files: Dict[str, List[str]] = {}

    for p in paths:
        dir_path = os.path.dirname(p)
        file_name = os.path.basename(p)
        if not dir_path and not file_name:
            continue

        dir_to_files.setdefault(dir_path, [])
        if file_name and file_name not in dir_to_files[dir_path]:
            dir_to_files[dir_path].append(file_name)

    # 3) 디렉터리별 요약 문자열 생성
    segments: List[str] = []

    for dir_path in sorted(dir_to_files.keys()):
        files = dir_to_files[dir_path]

        # 파일 목록을 패밀리 기준으로 다시 요약
        files_str = summarize_files_in_dir(files)

        short_dir = shorten_dir_path(dir_path)
        if short_dir:
            segments.append(f"{short_dir}\\ ({files_str})")
        else:
            segments.append(files_str)

    return "; ".join(segments)


def summarize_directories(raw_str: str) -> str:
    r"""
    Directories 컬럼 요약:
    - 볼륨 GUID → C:로 치환
    - 상위/하위가 겹치면 리프 디렉터리만 남기기
    - 경로도 shorten_dir_path 로 축약
    """
    if not raw_str:
        return ""

    dirs = [normalize_volume(d) for d in raw_str.split(",") if d.strip()]
    dirs = list(set(dirs))

    leaf_dirs: List[str] = []
    for d in dirs:
        is_prefix = False
        for other in dirs:
            if d == other:
                continue
            if other.startswith(d.rstrip("\\") + "\\"):
                is_prefix = True
                break
        if not is_prefix:
            leaf_dirs.append(d)

    short_leaf = [shorten_dir_path(d) for d in leaf_dirs]
    return ", ".join(sorted(short_leaf))


# ===============================
# 3. TIME 태그: LastRun 기준
# ===============================

def parse_lastrun(last_run_str: str) -> Optional[datetime]:
    """
    PECmd LastRun 문자열을 datetime으로 변환.
    - 문자열 안에서 'YYYY-MM-DD HH:MM:SS(.ffffff)' 패턴만 뽑아서 파싱
    """
    if not last_run_str:
        return None

    s = last_run_str.strip()
    if not s:
        return None

    s = s.replace("T", " ")

    m = re.search(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)", s
    )
    if m:
        core = m.group(1)
    else:
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(core, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(core)
    except ValueError:
        return None


def get_time_tags(last_run: Optional[datetime],
                  ref_time: Optional[datetime]) -> List[str]:
    """
    - LastRun이 존재하면: TIME_ACCESSED
    - ref_time 과 LastRun 차이 절댓값 기준으로
      RECENT / WEEK / MONTH / OLD 중 **하나만** 붙인다.
    """
    tags: List[str] = []
    if last_run:
        tags.append("TIME_ACCESSED")

    if last_run and ref_time:
        diff = ref_time - last_run
        days = abs(diff.total_seconds()) / 86400.0

        # 가장 좁은 구간 하나만 선택 (if / elif)
        if days <= 1:
            tags.append("TIME_RECENT")
        elif days <= 7:
            tags.append("TIME_WEEK")
        elif days <= 30:
            tags.append("TIME_MONTH")
        elif days > 30:
            tags.append("TIME_OLD")

    return tags


# ===============================
# 4. output 파일명 충돌 처리 (_v1, _v2 ...)
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
# 6. description 빌더
# ===============================

def build_description(row: Dict[str, str]) -> str:
    """
    한 행(row)에서:
      - LastRun / Tags / tag / SourceAccessed / Note / Version 은
        별도 컬럼이거나 필요 없으니까 description에서 제외
      - 나머지 컬럼은 "Key:Value" 형태로 이어붙여 descrition 생성
    구분자: " | "
    """
    exclude_keys = {
        "LastRun", "Tags", "tag",
        "SourceAccessed", "Note", "Version"
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
# 7. 프리패치 CSV 태깅
#    -> (type / lastwritetimestemp / descrition / tag)
# ===============================

def tag_prefetch_csv(input_path: Path,
                     ref_time: Optional[datetime],
                     output_dir: Path,
                     case_name: Optional[str]) -> Path:
    """
    - input_path: *_PECmd_Output.csv 전체 경로
    - ref_time  : 파일명에서 뽑은 기준 시각
    - output_dir: <드라이브>:\tagged 디렉터리
    - case_name : Kape Output 하위 1단계 폴더 이름 (예: Jo, Terry)

    최종 출력 컬럼:
      1) type               -> "ARTIFACT_PREFETCH" 고정
      2) lastwritetimestemp -> LastRun 원본 문자열
      3) descrition         -> 나머지 필드를 "Key:Value | ..." 형태로 묶은 문자열
      4) tag                -> 우리가 부여한 태그 (쉼표 구분)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    input_basename = input_path.name
    base_no_ext, _ = os.path.splitext(input_basename)

    # 파일명: 원래 이름 + CASE 이름 + _Tagged.csv
    if case_name:
        output_filename = f"{base_no_ext}_{case_name}_Tagged.csv"
    else:
        output_filename = f"{base_no_ext}_Tagged.csv"

    output_path = ensure_unique_output_path(output_dir / output_filename)

    with input_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         output_path.open("w", encoding="utf-8-sig", newline="") as f_out:

        reader = csv.DictReader(f_in)

        # 최종 컬럼은 공통 4개
        fieldnames = ["type", "lastwritetimestemp", "descrition", "tag"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            tags: List[str] = []

            # ===== 기본 태그 =====
            tags.append("ARTIFACT_PREFETCH")
            tags.append("AREA_WINDOWS")
            tags.append("AREA_PREFETCH")
            tags.append("EVENT_EXECUTED")
            tags.append("STATE_ACTIVE")

            # ===== Directories / FilesLoaded 요약 =====
            orig_dirs = row.get("Directories", "") or row.get("DirectoriesLoaded", "")
            orig_files = row.get("FilesLoaded", "")

            row["Directories"] = summarize_directories(orig_dirs)
            row["FilesLoaded"] = summarize_files_list(orig_files)

            # ===== SourceFilename: 경로 제거, 파일명만 =====
            if "SourceFilename" in row:
                row["SourceFilename"] = os.path.basename(row["SourceFilename"] or "")

            # ===== TIME 태그 (LastRun 기준) =====
            last_run_str = row.get("LastRun", "") or ""
            last_run_dt = parse_lastrun(last_run_str)
            tags.extend(get_time_tags(last_run_dt, ref_time))

            # ===== descrition 생성 =====
            desc = build_description(row)

            # ===== tag 문자열 정리 =====
            tags = sorted(set(tags))
            tag_str = ",".join(tags)

            # ===== 최종 출력용 row 구성 =====
            out_row = {
                "type": "ARTIFACT_PREFETCH",
                "lastwritetimestemp": last_run_str.strip(),
                "descrition": desc,
                "tag": tag_str,
            }

            writer.writerow(out_row)

    return output_path


# ===============================
# 8. main (D:~Z: + Kape Output 스캔)
# ===============================

def main():
    print("[PECmd] D:~Z: + 'Kape Output' 경로에서 *_PECmd_Output.csv 탐색 중...")

    candidates = find_pecmd_csvs_under_ccit()
    if not candidates:
        print("[-] *_PECmd_Output.csv 파일을 찾지 못했습니다.")
        return

    for input_path, ref_time in candidates:
        print(f"[+] 입력 파일: {input_path}")
        if ref_time:
            print(f"    -> 파일명 기준 기준 시각(ref_time): {ref_time}")
        else:
            print("    -> ref_time 없음 (TIME_RECENT/WEEK/MONTH/OLD 태그는 생략될 수 있음)")

        # Kape Output 하위 1단계 폴더명(case) 추출
        case_name = get_kape_child_folder_name(input_path)
        if case_name:
            print(f"    -> Kape Output CASE 폴더: {case_name}")
        else:
            print("    -> Kape Output CASE 폴더를 찾지 못함 (파일명에 CASE 미반영)")

        # 출력 디렉터리: 드라이브 루트의 tagged (예: D:\tagged)
        drive = input_path.drive or "D:"
        output_dir = Path(drive + "\\tagged")
        print(f"    -> 출력 디렉터리: {output_dir}")

        output_path = tag_prefetch_csv(input_path, ref_time, output_dir, case_name)
        print(f"    -> 태깅 완료. 결과 파일: {output_path}")


def run(*args, **kwargs):
    """
    오케스트레이터에서 run(...) 형태로 호출해도 되도록 래핑.
    (인자는 무시하고 D:~Z: + 'Kape Output' 스캔만 수행)
    """
    main()


if __name__ == "__main__":
    main()
