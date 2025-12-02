#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import json
from pathlib import Path

csv.field_size_limit(10 * 1024 * 1024)

# ============================================================
# BASE_OUT 탐색 (기존 태그 코드와 동일 규칙)
# ============================================================

def _existing_data_drives():
    """C:를 제외한 실제 존재하는 드라이브 목록 (D:~Z:)"""
    drives = []
    for code in range(ord("D"), ord("Z") + 1):
        root = Path(f"{chr(code)}:\\")
        if root.exists():
            drives.append(chr(code))
    return drives

def resolve_e01_path():
    """
    D:~Z: 각 드라이브의 \\ccit\\*.e01 중 첫 번째를 사용.
    (환경변수 사용 안 함)
    """
    candidates = []
    for d in _existing_data_drives():
        ccit_root = Path(f"{d}:\\ccit")
        if not ccit_root.is_dir():
            continue
        try:
            for hit in ccit_root.rglob("*.e01"):
                candidates.append(hit)
        except Exception as e:
            print(f"[WARN] {ccit_root} 검색 중 예외 발생: {e}")

    if not candidates:
        print("[ERR ] E01 이미지를 찾지 못했습니다. (D:~Z:\\ccit\\*.e01 없음)")
        return None

    candidates = sorted(candidates, key=lambda p: (p.drive, str(p).lower()))
    chosen = candidates[0]
    print(f"[INFO] JSONL 기준 E01: {chosen}")
    return chosen

def find_base_out_from_e01():
    """
    BASE_OUT = <E01가 있는 드라이브>:\\Kape Output
    """
    e01 = resolve_e01_path()
    if not e01:
        return None
    drive = e01.drive or "D:"
    base_out = Path(drive + r"\Kape Output")
    if not base_out.is_dir():
        print(f"[ERR ] BASE_OUT 폴더가 존재하지 않습니다: {base_out}")
        return None
    print(f"[INFO] BASE_OUT: {base_out}")
    return base_out

# ============================================================
# CSV → JSONL 변환 유틸
# ============================================================

# time 컬럼 후보를 찾을 때 사용할 키워드 (컬럼명에 포함되면 후보로 간주)
TIME_KEYWORDS = [
    "time",        # TimeCreated, timestamp 등
    "date",        # date_time, Date 등
    "lastwrite",   # LastWriteTimestamp 등
    "record"       # RecordWriteTime 등
]

def infer_artifact_type(csv_path: Path) -> str:
    """
    CSV 파일명 기반으로 아티팩트 타입 문자열 생성
    예) eventlog_4688_tagged.csv -> eventlog_4688
        레지스트리_하위키이름_tagged.csv -> 레지스트리_하위키이름
    """
    stem = csv_path.stem
    if stem.endswith("_tagged"):
        stem = stem[:-7]
    return stem

def get_last_time_column(row: dict) -> tuple[str, str]:
    """
    컬럼명에 TIME_KEYWORDS 키워드를 포함하고, 값이 non-empty인 첫 번째 컬럼을 '시간'으로 사용.
    반환: (값, 사용한 컬럼명) / 없으면 ("", "")
    """
    # DictReader가 주는 키 순서 그대로 사용
    for col in row.keys():
        col_lower = str(col).lower()
        if any(kw in col_lower for kw in TIME_KEYWORDS):
            val = str(row.get(col, "")).strip()
            if val:
                return val, col
    return "", ""

def build_kv_string(row: dict, exclude_keys: set[str]) -> str:
    """
    컬럼별 key:value를 " | " 구분자로 이어붙인 문자열 생성.
    exclude_keys 에 포함된 컬럼은 제외 (예: time 컬럼, tags 컬럼 등)
    """
    parts = []
    for k, v in row.items():
        if k in exclude_keys:
            continue
        if v is None:
            continue
        v_str = str(v).strip()
        if not v_str:
            continue
        parts.append(f"{k}:{v_str}")
    return " | ".join(parts)

def csv_to_jsonl(csv_path: Path, jsonl_path: Path):
    """
    하나의 tag CSV → 대응하는 JSONL 파일로 변환.
    출력 한 줄 구조:
      artifact_type / time / description / tag / source_csv
    """
    count = 0
    artifact_type = infer_artifact_type(csv_path)

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f_in, \
         jsonl_path.open("w", encoding="utf-8") as f_out:
        
        reader = csv.DictReader(f_in)
        for row in reader:
            # 1) 마지막 사용 시간 후보 잡기
            last_time, time_col = get_last_time_column(row)

            # 2) 태그 (태그 코드에서 추가한 tags 컬럼)
            tags_str = str(row.get("tags", "")).strip()

            # 3) description: 나머지 컬럼들을 key:value | ... 형식으로
            exclude = {"tags"}
            if time_col:
                exclude.add(time_col)
            description = build_kv_string(row, exclude)

            # 4) JSONL 레코드 구성
            record = {
                "artifact_type": artifact_type,   # 예: eventlog_4688, 레지스트리_하위키이름
                "time": last_time,               # 예: 2025-11-14 10:23:45 또는 2025.11.14 등 원본 그대로
                "description": description,      # 예: access:24 | produce:1 | ...
                "tag": tags_str,                 # 태그 코드에서 지정된 태그 문자열
                "source_csv": str(csv_path)      # 원본 CSV 전체 경로
            }

            f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"[OK] {csv_path.name} -> {jsonl_path.name} ({count} lines)")

# ============================================================
# 메인: BASE_OUT 기준으로 tag 폴더 내 CSV → JSONL
# ============================================================

def main():
    base_out = find_base_out_from_e01()
    if not base_out:
        return

    # BASE_OUT 아래의 각 드라이브 루트(H, E 등)를 순회
    for drive_root in sorted(p for p in base_out.iterdir() if p.is_dir()):
        tag_root = drive_root / "tag"
        if not tag_root.is_dir():
            continue

        print(f"\n[DRIVE] JSONL 변환 대상 tag 루트: {tag_root}")

        # tag_root 이하의 모든 CSV를 JSONL로 변환
        for csv_path in tag_root.rglob("*.csv"):
            # JSONL 파일 경로: 같은 위치, 확장자만 .jsonl
            jsonl_path = csv_path.with_suffix(".jsonl")
            print(f"[STEP] CSV → JSONL: {csv_path} -> {jsonl_path}")
            try:
                csv_to_jsonl(csv_path, jsonl_path)
            except UnicodeDecodeError as e:
                print(f"[SKIP] 디코딩 오류로 스킵: {csv_path} ({e})")
            except Exception as e:
                print(f"[ERR ] 변환 중 예외 발생, 스킵: {csv_path} ({e})")

if __name__ == "__main__":
    main()
