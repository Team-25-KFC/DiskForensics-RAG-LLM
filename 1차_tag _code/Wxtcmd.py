import pandas as pd
from pathlib import Path
from typing import Iterator


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
# Tagger
# ============================================================

class WxTActivityTagger:
    """Windows Timeline - Activity.csv 최소 태깅기"""

    def __init__(self):
        self.now = pd.Timestamp.now()
        self.one_day = self.now - pd.Timedelta(days=1)
        self.one_week = self.now - pd.Timedelta(days=7)
        self.one_month = self.now - pd.Timedelta(days=30)

    def get_time_tag(self, ts):
        if ts is None or pd.isna(ts) or ts == "":
            return None
        try:
            ts = pd.to_datetime(ts)
        except Exception:
            return None

        if ts >= self.one_day:
            return "TIME_RECENT"
        if ts >= self.one_week:
            return "TIME_WEEK"
        if ts >= self.one_month:
            return "TIME_MONTH"
        return "TIME_OLD"

    def get_area_tag(self, exe: str):
        if not exe:
            return None
        exe = exe.lower()

        if exe.startswith("microsoft"):
            return "AREA_SYSTEM"
        if exe.endswith(".exe"):
            return "AREA_PROGRAMFILES"
        return None

    def get_activity_tag(self, atype):
        try:
            atype = int(atype)
        except Exception:
            return "ACT_UNKNOWN"

        if atype == 11:
            return "ACT_EXECUTE"
        return "ACT_UNKNOWN"

    def process_csv(self, csv_path: Path, output_root: Path):
        csv_path = Path(csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        out_rows = []

        for _, row in df.iterrows():
            start = row.get("StartTime")
            exe = row.get("Executable", "")
            act = row.get("ActivityType", "")

            time_tag = self.get_time_tag(start)
            act_tag = self.get_activity_tag(act)
            area_tag = self.get_area_tag(exe)

            tags = ["ARTIFACT_TIMELINE_WXT", act_tag]
            if time_tag:
                tags.append(time_tag)
            if area_tag:
                tags.append(area_tag)

            desc = f"Executable: {exe} | ActivityType: {act}"

            out_rows.append(
                {
                    "Type": "WXTCMD_ACTIVITY",
                    "LastWriteTimestamp": start,
                    "description": desc,
                    "Tags": " | ".join(tags),
                }
            )

        output_root.mkdir(parents=True, exist_ok=True)
        out_file = ensure_unique_output_path(output_root / f"{csv_path.stem}_tagged.csv")
        pd.DataFrame(out_rows).to_csv(out_file, index=False, encoding="utf-8-sig")

        return str(out_file), len(out_rows)


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":
    tagger = WxTActivityTagger()
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs():
        out_root = drive_root / "tagged" / case_name / "Wxtcmd"
        out_root.mkdir(parents=True, exist_ok=True)

        csv_files = []
        for p in case_dir.rglob("*.csv"):
            n = p.name.lower()
            if "_tagged" in n:
                continue
            if "wxt_" not in n:
                continue
            if "ids" in n:
                continue
            if not n.endswith("_activity.csv"):
                continue
            csv_files.append(p)

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | Wxt Activity {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                out, cnt = tagger.process_csv(csv_path, out_root)
                print(f"[{i}] 완료 → {out} ({cnt}행)")
                total += 1
            except Exception as e:
                print(f"[ERR] {csv_path} → {e}")

    print("\n=== Wxtcmd done:", total, "===")
