import pandas as pd
import re
from pathlib import Path

class WxTActivityTagger:
    """
    Windows Timeline - Activity.csv 전용 최소 구성 태깅기
    """

    def __init__(self):
        self.now = pd.Timestamp.now()
        self.one_day = self.now - pd.Timedelta(days=1)
        self.one_week = self.now - pd.Timedelta(days=7)
        self.one_month = self.now - pd.Timedelta(days=30)

    # -----------------------------
    # TIME TAG
    # -----------------------------
    def get_time_tag(self, ts):
        if ts is None or pd.isna(ts) or ts == "":
            return None
        try:
            ts = pd.to_datetime(ts)
        except:
            return None

        if ts >= self.one_day:
            return "TIME_RECENT"
        if ts >= self.one_week:
            return "TIME_WEEK"
        if ts >= self.one_month:
            return "TIME_MONTH"
        return "TIME_OLD"

    # -----------------------------
    # AREA TAG (Executable 기반)
    # -----------------------------
    def get_area_tag(self, exe: str):
        if not exe:
            return None
        exe = exe.lower()

        if exe.startswith("microsoft"):
            return "AREA_SYSTEM"
        if exe.endswith(".exe"):
            return "AREA_PROGRAMFILES"
        return None

    # -----------------------------
    # ACTIVITY TYPE TAG
    # -----------------------------
    def get_activity_tag(self, atype):
        try:
            atype = int(atype)
        except:
            return "ACT_UNKNOWN"

        if atype == 11:
            return "ACT_EXECUTE"

        return "ACT_UNKNOWN"

    # -----------------------------
    # 태깅 메인
    # -----------------------------
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

            out_rows.append({
                "Type": "WXTCMD_ACTIVITY",
                "LastWriteTimestamp": start,
                "description": desc,
                "Tags": " | ".join(tags)
            })

        out_df = pd.DataFrame(out_rows)

        output_root.mkdir(parents=True, exist_ok=True)
        out_file = output_root / f"{csv_path.stem}_tagged.csv"
        out_df.to_csv(out_file, index=False, encoding="utf-8-sig")

        return str(out_file), len(out_rows)


# -----------------------------
# 실행부
# -----------------------------
if __name__ == "__main__":
    base = Path(__file__).resolve().parent
    input_root = base
    out_root = base / "csvtag_output"
    out_root.mkdir(exist_ok=True)

    tagger = WxTActivityTagger()

csv_files = []

for p in input_root.rglob("*.csv"):
    name = p.name.lower()

    # wxt 파일만 처리
    if "wxt_" not in name:
        continue

    # IDs 포함된 파일 제외
    if "ids" in name:
        continue

    # Activity 파일만 처리
    if not name.endswith("_activity.csv"):
        continue

    csv_files.append(p)

    if not csv_files:
        print("Activity CSV 없음.")
    else:
        print(f"{len(csv_files)}개 Activity 파일 태깅 시작")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                out, cnt = tagger.process_csv(csv_path, out_root)
                print(f"[{i}] 완료 → {out} ({cnt}행)")
            except Exception as e:
                print(f"[ERR] {csv_path} → {e}")

