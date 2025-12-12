import re
from pathlib import Path
from typing import Iterator

import pandas as pd


# ============================================================
# 공통 유틸 (D~Z:\Kape Output\<case>\...)
# ============================================================

def iter_case_dirs() -> Iterator[tuple[Path, str, Path]]:
    for code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(code)}:/")
        kape_root = drive_root / "Kape Output"
        if not kape_root.is_dir():
            continue
        for case_dir in kape_root.iterdir():
            if case_dir.is_dir():
                yield drive_root, case_dir.name, case_dir


def ensure_unique_output_path(path: Path) -> Path:
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
# Boot Tagger
# ============================================================

class BootTagger:
    """
    MFTECmd $Boot CSV 전용 태거 (최소 구성)
    - 악성 판단 X
    - NTFS 메타데이터를 정규화해서 Tags/description으로 남김
    """

    def build_description(self, row):
        fields = [
            "BytesPerSector",
            "SectorsPerCluster",
            "ClusterSize",
            "MftClusterBlockNumber",
            "MftMirrClusterBlockNumber",
            "MftEntrySize",
            "IndexEntrySize",
            "TotalSectors",
            "VolumeSerialNumber",
            "SourceFile",
        ]

        out = []
        for f in fields:
            if f in row.index and pd.notna(row[f]) and str(row[f]).strip() != "":
                out.append(f"{f}: {row[f]}")
        return " | ".join(out)

    def build_tags(self, row):
        tags = ["ARTIFACT_MFT_BOOT", "STATE_SYSTEM"]

        bps = row.get("BytesPerSector")
        if pd.notna(bps) and str(bps).strip() != "":
            tags.append(f"NTFS_BPS_{bps}")

        cs = row.get("ClusterSize")
        if pd.notna(cs) and str(cs).strip() != "":
            tags.append(f"NTFS_CLUSTER_{cs}")

        mft_cluster = row.get("MftClusterBlockNumber")
        if pd.notna(mft_cluster) and str(mft_cluster).strip() != "":
            tags.append(f"MFT_START_CLUSTER_{mft_cluster}")

        serial = row.get("VolumeSerialNumber")
        if pd.notna(serial) and str(serial).strip() != "":
            tags.append(f"NTFS_SERIAL_{serial}")

        return " | ".join(dict.fromkeys(tags))

    def process_csv(self, csv_path: Path, output_root: Path):
        csv_path = Path(csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        out_rows = []
        for _, row in df.iterrows():
            desc = self.build_description(row)
            tags = self.build_tags(row)

            out_rows.append(
                {
                    "Type": "MFT_BOOT",
                    "LastWriteTimestamp": None,
                    "description": desc,
                    "Tags": tags,
                }
            )

        output_root.mkdir(parents=True, exist_ok=True)
        out_csv = ensure_unique_output_path(output_root / f"{csv_path.stem}_tagged.csv")
        pd.DataFrame(out_rows).to_csv(out_csv, index=False, encoding="utf-8-sig")

        return str(out_csv), len(out_rows)


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":
    tagger = BootTagger()
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs():
        out_root = drive_root / "tagged" / case_name / "MFTCmd_Boot"
        out_root.mkdir(parents=True, exist_ok=True)

        csv_files = [
            p for p in case_dir.rglob("*MFTECmd_Boot*.csv")
            if "_tagged" not in p.name.lower()
        ]

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | Boot {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
                out_csv, cnt = tagger.process_csv(csv_path, out_root)
                print(f"  → 완료: {out_csv} ({cnt}행)")
                total += 1
            except Exception as e:
                print(f"  오류: {e}")

    print("\n=== MFTCmd_Boot done:", total, "===")
