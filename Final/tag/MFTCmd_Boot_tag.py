import re
from pathlib import Path
from typing import Iterator

import pandas as pd


def iter_case_dirs(debug: bool = False) -> Iterator[tuple[Path, str, Path]]:
    r"""
    D:~Z:\Kape Output\<case_name>\... 구조
    yields: (drive_root, case_name, case_dir)
    """
    for code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(code)}:/")
        kape_root = drive_root / "Kape Output"

        if not kape_root.is_dir():
            continue

        for case_dir in [p for p in kape_root.iterdir() if p.is_dir()]:
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


def sanitize_for_filename(s: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "_", str(s)).strip()


class BootTagger:
    def build_description(self, row):
        fields = [
            "BytesPerSector", "SectorsPerCluster", "ClusterSize",
            "MftClusterBlockNumber", "MftMirrClusterBlockNumber",
            "MftEntrySize", "IndexEntrySize", "TotalSectors",
            "VolumeSerialNumber", "SourceFile",
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

    def process_csv(self, csv_path: Path, output_root: Path, case_name: str):
        df = pd.read_csv(csv_path, low_memory=False)

        out_rows = []
        for _, row in df.iterrows():
            out_rows.append(
                {
                    "Type": "MFT_BOOT",
                    "LastWriteTimestamp": None,
                    "description": self.build_description(row),
                    "Tags": self.build_tags(row),
                }
            )

        output_root.mkdir(parents=True, exist_ok=True)
        safe_case = sanitize_for_filename(case_name)
        out_name = f"{Path(csv_path).stem}_{safe_case}_normalized.csv"
        out_csv = ensure_unique_output_path(output_root / out_name)

        pd.DataFrame(out_rows).to_csv(out_csv, index=False, encoding="utf-8-sig")
        return str(out_csv), len(out_rows)


if __name__ == "__main__":
    tagger = BootTagger()
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs(debug=False):
        output_root = drive_root / "tagged"

        # ✅ 여기만 핵심 수정: $Boot / Boot 어떤 형태든 잡게
        csv_files = []
        for p in case_dir.rglob("*.csv"):
            n = p.name.lower()
            if "_tagged" in n or "_normalized" in n:
                continue
            if "mftecmd" not in n:
                continue
            # Boot 관련만
            if "boot" not in n:
                continue
            # (혹시 USN $J랑 섞였으면 제외)
            if "usnjrnl" in n or "$j" in n:
                continue
            csv_files.append(p)

        if not csv_files:
            continue

        for csv_path in csv_files:
            try:
                out_csv, cnt = tagger.process_csv(csv_path, output_root, case_name)
                total += 1
            except Exception:
                pass

    print("\n=== MFTCmd_Boot done:", total, "===")
