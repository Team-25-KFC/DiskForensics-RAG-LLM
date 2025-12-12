import os
import re
from pathlib import Path
from typing import List, Optional, Tuple, Iterator

import pandas as pd


# ============================================================
# 공통 유틸 (클래스 밖, 모듈 레벨)
# ============================================================

def iter_case_dirs() -> Iterator[tuple[Path, str, Path]]:
    """
    D:~Z:\Kape Output\<case_name>\... 구조에서 case_dir들을 yield
    returns: (drive_root, case_name, case_dir)
    """
    for code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(code)}:/")
        kape_root = drive_root / "Kape Output"
        if not kape_root.is_dir():
            continue

        for case_dir in kape_root.iterdir():
            if case_dir.is_dir():
                yield drive_root, case_dir.name, case_dir


def ensure_unique_output_path(path: Path) -> Path:
    """이미 있으면 _1, _2 ... 붙여서 덮어쓰기 방지"""
    if not path.exists():
        return path
    parent, stem, suffix = path.parent, path.stem, path.suffix
    i = 1
    while True:
        cand = parent / f"{stem}_{i}{suffix}"
        if not cand.exists():
            return cand
        i += 1


# ============================================================
# MFT Tagger
# ============================================================

class MFTTagger:
    """
    MFTECmd CSV → 1차 태깅 CSV (미니멀 구성)
    지원 대상:
        - MFTECmd_$MFT
        - MFTECmd_$FileListing
        - MFTECmd_DumpResidentFiles
    """

    def __init__(self):
        self.now = pd.Timestamp.now()
        self.one_day_ago = self.now - pd.Timedelta(days=1)
        self.one_week_ago = self.now - pd.Timedelta(days=7)
        self.one_month_ago = self.now - pd.Timedelta(days=30)

        self.exec_ext = {".exe", ".dll", ".sys", ".scr", ".com"}
        self.script_ext = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"}

    # ============================================================
    # 공통 유틸 (클래스 메서드)
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
    # KIND 판별 (Boot/J 파일 스킵 우선)
    # ============================================================

    def detect_kind(self, csv_name: str):
        name = csv_name.lower()

        # 스킵 규칙은 최우선
        if "_boot" in name:
            return "IGNORE"
        if re.search(r'[_\-]j(\.|_|$)', name) or "_j" in name:
            return "IGNORE"

        if "_mft_dumpresidentfiles" in name:
            return "MFT_DUMP_RESIDENT"
        if "_filelisting" in name:
            return "MFT_FILE_LISTING"
        if "_mft_output" in name or "_mft_" in name:
            return "MFT_ENTRY"

        return "IGNORE"

    # ============================================================
    # 태깅 로직
    # ============================================================

    def tag_file(self, row, kind):
        tags = ["ARTIFACT_MFT", kind]

        ts = (
            row.get("LastModified0x10")
            or row.get("Created0x10")
            or row.get("LastRecordChange0x10")
            or row.get("LastAccess0x10")
        )
        t = self.get_time_tag(ts)
        if t:
            tags.append(t)

        if row.get("IsDirectory") in [1, True, "True"]:
            tags.append("STATE_DIRECTORY")

        if row.get("InUse") in [1, True, "True"]:
            tags.append("STATE_ACTIVE")
        elif row.get("InUse") in [0, False, "False"]:
            tags.append("STATE_DELETED")

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

    def process_csv(self, csv_path, output_root: Path):
        csv_path = Path(csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        kind = self.detect_kind(csv_path.name)
        if kind == "IGNORE":
            print(f"  → 스킵됨 (Boot/J/Unknown): {csv_path.name}")
            return None, 0

        if kind == "MFT_ENTRY":
            desc_fields = ["ParentPath", "FileName", "Extension", "FileSize", "InUse"]
        elif kind == "MFT_FILE_LISTING":
            desc_fields = ["FullPath", "Extension", "IsDirectory", "FileSize"]
        else:
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
        out_csv = ensure_unique_output_path(output_root / f"{csv_path.stem}_tagged.csv")
        out_df.to_csv(out_csv, index=False, encoding="utf-8-sig")

        return str(out_csv), len(out_rows)


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":
    tagger = MFTTagger()
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs():
        output_root = drive_root / "tagged" / case_name / "MFTCmd"
        output_root.mkdir(parents=True, exist_ok=True)

        csv_files = []
        for p in case_dir.rglob("*MFTECmd_*.csv"):
            n = p.name.lower()
            if "_tagged" in n:
                continue
            if "boot" in n:  # Boot는 Boot 스크립트 처리
                continue
            csv_files.append(p)

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | MFTECmd {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, start=1):
            print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
            try:
                out_csv, cnt = tagger.process_csv(csv_path, output_root)
                if out_csv:
                    print(f"  → 완료: {out_csv} ({cnt}행)")
                    total += 1
                else:
                    print("  → 스킵됨")
            except Exception as e:
                print(f"  오류: {e}")

    print("\n=== MFTCmd done:", total, "===")
