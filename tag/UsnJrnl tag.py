#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAPE MFTECmd_$J USN 저널 CSV → JSONL 1차 태그 변환 스크립트 (드라이브 전체 탐색 버전)

- 인자 없음, 고정 경로 없음.
- C: ~ Z: 모든 드라이브 루트를 훑어서, 이름이 정확히 'KAPE Output' 인 폴더를 찾는다.
- 각 'KAPE Output' 폴더 아래에서
    '**/*MFTECmd_$J_Output.csv'
  패턴에 매칭되는 CSV들을 모두 찾는다.
- 각 CSV와 같은 폴더 안에 'csvtag_output/<원본파일명>_tagged.jsonl' 을 생성한다.

전제:
- 외장하드에 E01 이 있고,
- 그 외장하드 안에 (예: E:\ccit\KAPE Output\...) 구조로 KAPE Output 이 생성되어 있다고 가정.
"""

import csv
import json
from pathlib import Path

# ─────────────────────── 태그용 기본 설정 ───────────────────────

EXECUTABLE_EXT = {".exe", ".dll", ".sys", ".scr", ".com"}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"}
DOC_EXT = {".doc", ".docx", ".pdf", ".rtf", ".txt", ".odt"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz"}
LOG_EXT = {".log"}

SUSPICIOUS_NAME_KEYWORDS = [
    "crack",
    "keygen",
    "mimikatz",
    "payload",
    "backdoor",
    "stealer",
    "miner",
    "rat",
]


def normalize_list_field(raw: str) -> str:
    """
    'FileCreate|DataExtend|Close' 같은 값을
    'FileCreate, DataExtend, Close' 로 변환.

    description 안에서 값 내부에 '|'가 남지 않게 하기 위함.
    """
    if not raw:
        return "(none)"

    parts = [raw]
    for sep in ("|", ","):
        new_parts = []
        for p in parts:
            new_parts.extend([x.strip() for x in p.split(sep)])
        parts = new_parts

    parts = [p for p in parts if p]
    return ", ".join(parts) if parts else "(none)"


def build_tags(row: dict) -> str:
    """
    한 USN 레코드에 대해 tag 문자열 생성.
    - ARTIFACT_ / EVENT_ / ACT_ / FORMAT_ / SEC_ / STATE_ 위주.
    - 네가 정의한 태그 집합만 사용.
    """
    tags = set()

    # 아티팩트 타입: 이 CSV는 전부 USN 저널 레코드
    tags.add("ARTIFACT_USN_JOURNAL")

    name = (row.get("Name") or "").lower()
    ext = (row.get("Extension") or "").lower()
    reasons_raw = row.get("UpdateReasons") or ""
    attrs_raw = row.get("FileAttributes") or ""

    # ── EVENT_ / ACT_ : UpdateReasons 기반 ──
    reason_tokens = [r.strip() for r in reasons_raw.split("|") if r.strip()]

    if any(r in reason_tokens for r in ("FileCreate", "ObjectCreate")):
        tags.add("EVENT_CREATE")
        tags.add("ACT_FILE_OPERATION")

    if any(r in reason_tokens for r in ("FileDelete", "ObjectDelete")):
        tags.add("EVENT_DELETE")
        tags.add("ACT_FILE_OPERATION")

    if any(
        r in reason_tokens
        for r in ("DataExtend", "DataOverwrite", "DataTruncation", "BasicInfoChange", "StreamChange")
    ):
        tags.add("EVENT_MODIFY")
        tags.add("ACT_FILE_OPERATION")

    if any(r in reason_tokens for r in ("RenameNewName", "RenameOldName")):
        tags.add("EVENT_RENAME")
        tags.add("ACT_FILE_OPERATION")

    # ── FORMAT_ / SEC_ : 확장자 + 이름 기반 ──
    if ext in EXECUTABLE_EXT:
        tags.add("FORMAT_EXECUTABLE")
        tags.add("SEC_EXECUTABLE")
    elif ext in SCRIPT_EXT:
        tags.add("FORMAT_SCRIPT")
        tags.add("SEC_SCRIPT")
    elif ext in DOC_EXT:
        tags.add("FORMAT_DOCUMENT")
    elif ext in ARCHIVE_EXT:
        tags.add("FORMAT_ARCHIVE")
    elif ext in LOG_EXT:
        tags.add("FORMAT_LOG")

    if any(kw in name for kw in SUSPICIOUS_NAME_KEYWORDS):
        tags.add("SEC_SUSPICIOUS_NAME")

    # ── STATE_ : FileAttributes 기반 ──
    attr_tokens = [a.strip() for a in attrs_raw.split("|") if a.strip()]

    if "Hidden" in attr_tokens:
        tags.add("STATE_HIDDEN")
    if "System" in attr_tokens:
        tags.add("STATE_SYSTEM")
    if "ReadOnly" in attr_tokens:
        tags.add("STATE_READONLY")
    if "Compressed" in attr_tokens:
        tags.add("STATE_COMPRESSED")

    return "|".join(sorted(tags))


def build_description(row: dict) -> str:
    """
    JSONL의 description 필드 생성.
    - 컬럼 사이 구분자: ' | '
    - 값 안에서는 '|'를 사용하지 않도록 가공.
    - 여기서는 "의미 + 식별자"만 남긴다.
      (UpdateSequenceNumber는 목적상 사용하지 않으므로 제외)
    """
    filename = row.get("Name") or "(none)"
    extension = row.get("Extension") or "(none)"
    entry = row.get("EntryNumber") or "(none)"
    seq = row.get("SequenceNumber") or "(none)"
    p_entry = row.get("ParentEntryNumber") or "(none)"
    p_seq = row.get("ParentSequenceNumber") or "(none)"

    event_info = normalize_list_field(row.get("UpdateReasons") or "")
    file_attr = normalize_list_field(row.get("FileAttributes") or "")

    parts = [
        f"FileName : {filename}",
        f"Extension : {extension}",
        f"EventInfo : {event_info}",
        f"FileAttribute : {file_attr}",
        f"EntryNumber : {entry}",
        f"SequenceNumber : {seq}",
        f"ParentEntryNumber : {p_entry}",
        f"ParentSequenceNumber : {p_seq}",
    ]
    return " | ".join(parts)


def convert_single_csv(input_csv: Path, output_jsonl: Path) -> int:
    """
    단일 MFTECmd_$J_Output.csv → tagged JSONL 로 변환.

    반환값: 처리한 레코드 수
    """
    if not input_csv.exists():
        raise FileNotFoundError(f"입력 CSV를 찾을 수 없음: {input_csv}")

    count = 0
    with input_csv.open("r", encoding="utf-8-sig", newline="") as f_in, \
            output_jsonl.open("w", encoding="utf-8") as f_out:

        reader = csv.DictReader(f_in)

        for row in reader:
            last_ts = row.get("UpdateTimestamp") or ""

            record = {
                "Type": "USN_JOURNAL",
                "LastWriteTimestamp": last_ts,
                "description": build_description(row),
                "tag": build_tags(row),
            }
            f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    return count


def find_kape_output_roots() -> list[Path]:
    """
    C: ~ Z: 드라이브 루트에서 'KAPE Output' 폴더를 찾는다.

    - 각 드라이브 루트 바로 아래에 'KAPE Output' 이 있으면 사용
    - 또는, 루트 바로 아래 1-depth 폴더들 안에 'KAPE Output' 이 있으면 사용
      (예: E:\\ccit\\KAPE Output)
    """
    roots: list[Path] = []

    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        drive_root = Path(f"{letter}:\\")
        if not drive_root.exists():
            continue

        # 1) 루트 바로 아래
        kape_direct = drive_root / "KAPE Output"
        if kape_direct.is_dir():
            roots.append(kape_direct)

        # 2) 루트 아래 1-depth 디렉터리의 자식으로 존재하는 경우
        try:
            for child in drive_root.iterdir():
                if not child.is_dir():
                    continue
                if child.name == "KAPE Output":
                    roots.append(child)
                else:
                    sub = child / "KAPE Output"
                    if sub.is_dir():
                        roots.append(sub)
        except PermissionError:
            # 일부 시스템 디렉터리는 접근 불가할 수 있으니 무시
            continue

    # 중복 제거
    uniq_roots = []
    seen = set()
    for r in roots:
        rp = r.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq_roots.append(rp)

    if not uniq_roots:
        raise SystemExit(
            "[에러] 어떤 드라이브에서도 'KAPE Output' 폴더를 찾지 못했음.\n"
            " - 외장하드나 케이스 폴더 안에 'KAPE Output' 이름으로 폴더가 있는지 확인해줘."
        )

    print("[정보] 찾은 KAPE Output 폴더들:")
    for r in uniq_roots:
        print(f"  - {r}")
    print()
    return uniq_roots


def find_usn_csvs(kape_root: Path):
    """
    주어진 KAPE Output 루트(kape_root) 아래에서
    '*MFTECmd_$J_Output.csv' 패턴에 매칭되는 파일 모두 찾기 (재귀).
    """
    pattern = "**/*MFTECmd_$J_Output.csv"
    return list(kape_root.glob(pattern))


def main():
    # 1) 모든 드라이브에서 KAPE Output 루트(들) 찾기
    kape_roots = find_kape_output_roots()

    total_records_all = 0
    total_csv_files = 0

    for kape_root in kape_roots:
        csv_files = find_usn_csvs(kape_root)

        if not csv_files:
            print(f"[정보] '{kape_root}' 아래에서 MFTECmd_$J_Output.csv 파일을 찾지 못함.\n")
            continue

        print(f"[정보] '{kape_root}' 에서 찾은 MFTECmd_$J CSV 개수: {len(csv_files)}\n")
        total_csv_files += len(csv_files)

        for csv_path in csv_files:
            # CSV가 있는 폴더 기준으로 하위에 csvtag_output 폴더 생성
            out_dir = csv_path.parent / "csvtag_output"
            out_dir.mkdir(exist_ok=True)

            out_name = csv_path.stem + "_tagged.jsonl"
            out_path = out_dir / out_name

            count = convert_single_csv(csv_path, out_path)
            total_records_all += count

            print(f"[OK] {csv_path}")
            print(f"     -> {out_path} (레코드 {count}개)\n")

    print(f"[완료] 처리한 CSV 파일 수: {total_csv_files}")
    print(f"[완료] 전체 레코드 수: {total_records_all}")


if __name__ == "__main__":
    main()
