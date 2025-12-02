#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KAPE EvtxECmd 이벤트로그 CSV → CSV + JSONL 태그 변환 스크립트 (드라이브 전체 탐색, 청크 처리)

- 인자 없음, 고정 경로 없음.
- C: ~ Z: 모든 드라이브 루트를 훑어서, 이름이 'KAPE Output' 계열인 폴더를 찾는다.
  (예: 'KAPE Output', 'Kape Output', 'kape_output' 등: 공백/언더바/대소문자 무시)
- 각 KAPE Output 폴더 아래에서
    '**/*EvtxECmd*_Output.csv'
  패턴에 매칭되는 CSV들을 모두 찾는다.
- 각 CSV가 있는 폴더 안에
    'csvtag_output/<원본파일명>_tagged.csv'
    'csvtag_output/<원본파일명>_tagged.jsonl'
  을 생성한다.

전제:
- 외장하드에 E01 이 있고,
- 그 외장하드 안에 (예: E:\\ccit\\KAPE Output\\...) 구조로 KAPE Output 이 생성되어 있다고 가정.
"""

import csv
import json
import math
from pathlib import Path

import pandas as pd


# ─────────────────────── 유틸 / 공통 설정 ───────────────────────

def _norm_name(name: str) -> str:
    """폴더 이름 비교용: 공백/언더바 제거 + 소문자."""
    return name.lower().replace(" ", "").replace("_", "")


PARSER_KEY = "EvtxECmd"          # EvtxECmd 결과만 대상
CSV_TAG_SUBDIR_NAME = "csvtag_output"  # 각 CSV가 있는 폴더 아래에 생성


# ─────────────────────── 컬럼 가공 ───────────────────────

def normalize_time_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    TimeCreated 컬럼을 사람이 보기 좋은 문자열(YYYY-MM-DD HH:MM:SS)로 변환해서
    TimeCreated_fmt 컬럼에 넣어둔다.
    """
    if "TimeCreated" not in df.columns:
        df["TimeCreated_fmt"] = ""
        return df

    dt = pd.to_datetime(df["TimeCreated"], errors="coerce")
    df["TimeCreated_fmt"] = dt.dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def build_columns_dict(row: pd.Series) -> dict:
    """
    EvtxECmd CSV 한 행에서 우리가 쓰기로 한 필드만 뽑아서
    columns(dict) 구성.

    포함 키:
      - record_number    (RecordNumber)
      - event_record_id  (EventRecordId)
      - level            (Level)
      - provider         (Provider)
      - channel          (Channel)
      - computer         (Computer)
      - user             (UserName)
      - user_sid         (UserId)
      - desc             (MapDescription)
      - exe              (ExecutableInfo)
      - remote_host      (RemoteHost)
      - hidden_record    (HiddenRecord)
      - keywords         (Keywords)
      - payload          (Payload)  ← 전체 문자열
    """
    cols: dict = {}

    def add(label: str, value):
        if value is None:
            return
        if isinstance(value, float) and math.isnan(value):
            return
        if isinstance(value, str):
            v = value.strip()
            if not v or v.lower() == "nan":
                return
            value = v
        cols[label] = value

    add("record_number", row.get("RecordNumber"))
    add("event_record_id", row.get("EventRecordId"))

    add("level", row.get("Level"))
    add("provider", row.get("Provider"))
    add("channel", row.get("Channel"))
    add("computer", row.get("Computer"))

    add("user", row.get("UserName"))
    add("user_sid", row.get("UserId"))

    add("desc", row.get("MapDescription"))
    add("exe", row.get("ExecutableInfo"))
    add("remote_host", row.get("RemoteHost"))

    hidden = row.get("HiddenRecord")
    if hidden is not None and not (isinstance(hidden, float) and math.isnan(hidden)):
        add("hidden_record", hidden)

    add("keywords", row.get("Keywords"))

    payload = row.get("Payload")
    if isinstance(payload, str) and payload:
        # 더 이상 자르지 않고 전체 저장
        add("payload", payload)

    return cols


def build_key_values(row: pd.Series) -> str:
    """
    columns(dict)를 CSV 3번째 칸용 문자열로 변환:
    'key:value | key2:value2 ...'
    """
    cols = build_columns_dict(row)

    order = [
        "record_number",
        "event_record_id",
        "level",
        "provider",
        "channel",
        "computer",
        "user",
        "user_sid",
        "desc",
        "exe",
        "remote_host",
        "hidden_record",
        "keywords",
        "payload",
    ]

    parts = []
    for key in order:
        if key in cols:
            parts.append(f"{key}:{cols[key]}")
    # 혹시 나중에 컬럼 추가되면 뒤에 붙도록
    for key, value in cols.items():
        if key not in order:
            parts.append(f"{key}:{value}")

    return " | ".join(parts)


# ─────────────────────── TAG 규칙 ───────────────────────

def tag_event_row(row: pd.Series) -> str:
    """
    태그 규칙 (1차 버전):

      - 공통:
          ARTIFACT_EVENT_LOG, FORMAT_LOG

      - Security 채널 + 특정 EventId:
          * 4624, 4625, 4634, 4647, 4648
              → ACT_NETWORK_ACCESS, ACT_COMMUNICATION
          * 4720, 4722, 4723, 4724, 4725,
            4726, 4738, 4740, 4767, 4781
              → ACT_NETWORK_ACCESS
          * 4688
              → ACT_EXECUTE, EVENT_EXECUTED, SEC_EXECUTABLE
          * 1102
              → SEC_LOG_CLEARED
    """
    tags = set()

    tags.add("ARTIFACT_EVENT_LOG")
    tags.add("FORMAT_LOG")

    channel = str(row.get("Channel", "") or "")
    eid = row.get("EventId", None)

    try:
        eid_int = int(eid)
    except Exception:
        eid_int = None

    # Security 채널 - 로그인/로그오프
    if channel == "Security" and eid_int in {4624, 4625, 4634, 4647, 4648}:
        tags.add("ACT_NETWORK_ACCESS")
        tags.add("ACT_COMMUNICATION")

    # Security 채널 - 계정 관리
    if channel == "Security" and eid_int in {
        4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781
    }:
        tags.add("ACT_NETWORK_ACCESS")

    # Security 채널 - 프로세스 생성
    if channel == "Security" and eid_int == 4688:
        tags.add("ACT_EXECUTE")
        tags.add("EVENT_EXECUTED")
        tags.add("SEC_EXECUTABLE")

    # Security 채널 - 감사 로그 클리어
    if channel == "Security" and eid_int == 1102:
        tags.add("SEC_LOG_CLEARED")

    return "|".join(sorted(tags))


# ─────────────────────── CSV → CSV+JSONL 변환 (청크 처리) ───────────────────────

def convert_single_evtx_csv(csv_path: Path) -> tuple[int, Path, Path]:
    """
    EvtxECmd CSV 한 개를
      - tagged CSV (artifact_name / last_time / key_values / tags)
      - tagged JSONL (type / time / columns / tags[])
    로 변환.

    청크 단위로 읽어서 메모리 사용량을 줄인다.

    반환값: (레코드 수, csv_out_path, jsonl_out_path)
    """
    out_dir = csv_path.parent / CSV_TAG_SUBDIR_NAME
    out_dir.mkdir(parents=True, exist_ok=True)

    base_name = csv_path.stem
    csv_out = out_dir / f"{base_name}_tagged.csv"
    jsonl_out = out_dir / f"{base_name}_tagged.jsonl"

    # CSV/JSONL 파일을 스트리밍 모드로 열어둔다
    csv_f = csv_out.open("w", encoding="utf-8-sig", newline="")
    jsonl_f = jsonl_out.open("w", encoding="utf-8")

    csv_writer = csv.writer(csv_f)
    # CSV 헤더
    csv_writer.writerow(["artifact_name", "last_time", "key_values", "tags"])

    total_count = 0

    try:
        for chunk in pd.read_csv(csv_path, low_memory=False, chunksize=50000):
            chunk = normalize_time_column(chunk)

            for _, row in chunk.iterrows():
                eid = row.get("EventId")
                try:
                    eid_int = int(eid)
                    artifact_name = f"eventlog_{eid_int}"
                except Exception:
                    artifact_name = "eventlog_unknown"

                last_time = row.get("TimeCreated_fmt") or row.get("TimeCreated", "")

                columns_dict = build_columns_dict(row)
                key_values = build_key_values(row)

                tags_str = tag_event_row(row)
                tags_list = [t for t in tags_str.split("|") if t]

                # CSV 한 줄
                csv_writer.writerow([artifact_name, last_time, key_values, tags_str])

                # JSONL 한 줄
                obj = {
                    "type": artifact_name,
                    "time": last_time,
                    "columns": columns_dict,
                    "tags": tags_list,
                }
                jsonl_f.write(json.dumps(obj, ensure_ascii=False) + "\n")

                total_count += 1
    finally:
        csv_f.close()
        jsonl_f.close()

    return total_count, csv_out, jsonl_out


# ─────────────────────── KAPE Output 찾기 ───────────────────────

def find_kape_output_roots() -> list[Path]:
    """
    C:~Z: 드라이브 루트에서 'KAPE Output' 계열 폴더를 찾는다.

    - 루트 바로 아래에 'KAPE Output' 이 있으면 사용
    - 또는, 루트 바로 아래 1-depth 폴더들 안에 'KAPE Output' 이 있으면 사용
      (예: E:\\ccit\\KAPE Output)

    이름 비교는 공백/언더바/대소문자 무시하고 'kapeoutput' 기준으로 한다.
    """
    roots: list[Path] = []
    target = _norm_name("KAPE Output")

    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        drive_root = Path(f"{letter}:\\")
        if not drive_root.exists():
            continue

        try:
            for child in drive_root.iterdir():
                if not child.is_dir():
                    continue

                # child 자체가 KAPE Output 인 경우
                if _norm_name(child.name) == target:
                    roots.append(child)
                    continue

                # child 하위에 KAPE Output 이 있는 경우
                sub = child / "KAPE Output"
                if sub.is_dir():
                    roots.append(sub)
        except PermissionError:
            # 일부 시스템 디렉터리 접근 불가는 무시
            continue

    # 중복 제거
    uniq_roots: list[Path] = []
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


def find_evtx_csvs(kape_root: Path) -> list[Path]:
    """
    주어진 KAPE Output 루트(kape_root) 아래에서
    '**/*EvtxECmd*_Output.csv' 패턴에 매칭되는 파일 모두 찾기 (재귀).
    """
    pattern = "**/*EvtxECmd*_Output.csv"
    return list(kape_root.glob(pattern))


# ─────────────────────── 메인 ───────────────────────

def main():
    kape_roots = find_kape_output_roots()

    total_csv_files = 0
    total_records_all = 0

    for kape_root in kape_roots:
        evtx_csvs = find_evtx_csvs(kape_root)

        if not evtx_csvs:
            print(f"[정보] '{kape_root}' 아래에서 EvtxECmd CSV를 찾지 못함.\n")
            continue

        print(f"[정보] '{kape_root}' 에서 찾은 EvtxECmd CSV 개수: {len(evtx_csvs)}\n")
        total_csv_files += len(evtx_csvs)

        for csv_path in evtx_csvs:
            count, csv_out, jsonl_out = convert_single_evtx_csv(csv_path)
            total_records_all += count

            print(f"[OK] {csv_path}")
            print(f"     -> {csv_out}")
            print(f"     -> {jsonl_out} (레코드 {count}개)\n")

    print(f"[완료] 처리한 CSV 파일 수: {total_csv_files}")
    print(f"[완료] 전체 레코드 수: {total_records_all}")


if __name__ == "__main__":
    main()
