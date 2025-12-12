import os
import re
from pathlib import Path
from typing import List, Optional, Tuple
import pandas as pd


class MFTTagger:
    """
    MFTECmd CSV → 1차 태깅 CSV (미니멀 구성)
    지원 대상:
        - MFTECmd_$MFT
        - MFTECmd_$FileListing
    """

    def __init__(self):
        self.now = pd.Timestamp.now()
        self.one_day_ago = self.now - pd.Timedelta(days=1)
        self.one_week_ago = self.now - pd.Timedelta(days=7)
        self.one_month_ago = self.now - pd.Timedelta(days=30)

        # 최소 포맷탐지
        self.exec_ext = {".exe", ".dll", ".sys", ".scr", ".com"}
        self.script_ext = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"}

    # ============================================================
    # 공통 유틸
    # ============================================================

    def get_time_tag(self, ts):
        if ts is None or pd.isna(ts) or ts == "":
            return None

        try:
            ts = pd.to_datetime(ts)
        except Exception:
            return None

        if ts >= self.one_day_ago:
            return "TIME_RECENT"
        if ts >= self.one_week_ago:
            return "TIME_WEEK"
        if ts >= self.one_month_ago:
            return "TIME_MONTH"
        return "TIME_OLD"

    def build_description(self, row, fields):
        out = []
        for col in fields:
            if col in row.index and pd.notna(row[col]) and str(row[col]) != "":
                out.append(f"{col}: {row[col]}")
        return " | ".join(out)

    # ============================================================
    # KIND 판별 (Boot, J 파일 자동 스킵)
    # ============================================================

    def detect_kind(self, csv_name: str):
        name = csv_name.lower()

        if "_mft_dumpresidentfiles" in name:
            return "MFT_DUMP_RESIDENT"
        if "_filelisting" in name:
            return "MFT_FILE_LISTING"
        if "_mft_output" in name or "_mft_" in name:
            return "MFT_ENTRY"

        if "_boot" in name:
            return "IGNORE"
        if "_j" in name:
            return "IGNORE"

        return "IGNORE"

    # ============================================================
    # 태깅 로직 (최소 구성)
    # ============================================================

    def tag_file(self, row, kind):
        tags = ["ARTIFACT_MFT", kind]

        # Timestamp
        ts = (
            row.get("LastModified0x10")
            or row.get("Created0x10")
            or row.get("LastRecordChange0x10")
            or row.get("LastAccess0x10")
        )
        t = self.get_time_tag(ts)
        if t:
            tags.append(t)

        # Directory / Active / Deleted
        if row.get("IsDirectory") in [1, True, "True"]:
            tags.append("STATE_DIRECTORY")

        if row.get("InUse") in [1, True, "True"]:
            tags.append("STATE_ACTIVE")
        elif row.get("InUse") in [0, False, "False"]:
            tags.append("STATE_DELETED")

        # EXT 기반 최소 포맷
        ext = str(row.get("Extension", "") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext

        if ext in self.exec_ext:
            tags.append("FORMAT_EXECUTABLE")
            tags.append("SEC_EXECUTABLE")

        elif ext in self.script_ext:
            tags.append("FORMAT_SCRIPT")
            tags.append("SEC_SCRIPT")

        return " | ".join(dict.fromkeys(tags)), ts

    def tag_dump_resident(self, row):
        tags = ["ARTIFACT_MFT", "MFT_DUMP_RESIDENT"]

        ts = (
            row.get("TargetModified")
            or row.get("SourceModified")
            or row.get("TargetCreated")
            or row.get("SourceCreated")
        )

        t = self.get_time_tag(ts)
        if t:
            tags.append(t)

        return " | ".join(dict.fromkeys(tags)), ts

    # ============================================================
    # Main
    # ============================================================

    def process_csv(self, csv_path, output_root):
        csv_path = Path(csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        kind = self.detect_kind(csv_path.name)

        if kind == "IGNORE":
            print(f"  → 스킵됨 (Boot/J/Unknown): {csv_path.name}")
            return None, 0

        # Description 필드
        if kind == "MFT_ENTRY":
            desc_fields = ["ParentPath", "FileName", "Extension", "FileSize", "InUse"]
        elif kind == "MFT_FILE_LISTING":
            desc_fields = ["FullPath", "Extension", "IsDirectory", "FileSize"]
        else:  # Dump Resident
            desc_fields = ["RelativePath", "LocalPath", "FileSize", "DriveType"]

        out_rows = []

        for _, row in df.iterrows():
            if kind == "MFT_DUMP_RESIDENT":
                tags, ts = self.tag_dump_resident(row)
            else:
                tags, ts = self.tag_file(row, kind)

            desc = self.build_description(row, desc_fields)

            out_rows.append({
                "Type": kind,
                "LastWriteTimestamp": ts,
                "description": desc,
                "Tags": tags
            })

        out_df = pd.DataFrame(out_rows)

        output_root.mkdir(exist_ok=True, parents=True)
        out_csv = output_root / f"{csv_path.stem}_tagged.csv"
        out_df.to_csv(out_csv, index=False, encoding="utf-8-sig")

        return str(out_csv), len(out_rows)


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":
    base = Path(__file__).resolve().parent
    input_root = base
    output_root = base / "csvtag_output"
    output_root.mkdir(parents=True, exist_ok=True)

    tagger = MFTTagger()

    csv_files = [
        p for p in input_root.rglob("*MFTECmd_*.csv")
        if "_tagged" not in p.name
    ]

    if not csv_files:
        print("처리할 MFTECmd CSV 파일이 없습니다.")
    else:
        print(f"총 {len(csv_files)}개의 MFTECmd CSV 파일 발견.\n")

    for i, csv_path in enumerate(csv_files, start=1):
        print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
        try:
            out_csv, cnt = tagger.process_csv(csv_path, output_root)
            if out_csv:
                print(f"  → 완료: {out_csv} ({cnt}행)\n")
            else:
                print("  → 스킵됨\n")
        except Exception as e:
            print(f"  오류 발생: {e}\n")

    print("=== 모든 MFT CSV 처리 완료 ===")
