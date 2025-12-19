import csv
import os
import re
from pathlib import Path
from datetime import datetime, timedelta

NOW = datetime.now()

TARGET_PATTERN = "_RECmd_Batch_"

# ============================================================
# 1. D:~Z: Kape Output 하위 RECmd CSV 찾기
# ============================================================

def find_recmd_csvs():
    matches = []

    for drive_code in range(ord("D"), ord("Z") + 1):
        drive_root = f"{chr(drive_code)}:\\"
        if not os.path.exists(drive_root):
            continue

        kape_root = os.path.join(drive_root, "Kape Output")
        if not os.path.isdir(kape_root):
            continue

        for root, dirs, files in os.walk(kape_root):
            for fname in files:
                if TARGET_PATTERN in fname and fname.endswith(".csv") and "_tagged" not in fname:
                    matches.append(os.path.join(root, fname))

    return matches


# ============================================================
# 2. CASE 이름 추출
# ============================================================

def get_kape_child_folder_name(csv_path: str):
    p = Path(csv_path)
    for parent in [p] + list(p.parents):
        if parent.name.lower() == "kape output":
            try:
                rel = p.relative_to(parent)
            except ValueError:
                return None
            return rel.parts[0] if rel.parts else None
    return None


# ============================================================
# 3. 출력 경로 생성
# ============================================================

def get_tagged_output_path(csv_path: str, case_name: str | None):
    drive, _ = os.path.splitdrive(csv_path)
    base_dir = drive + "\\" if drive else os.path.dirname(csv_path)

    tagged_dir = os.path.join(base_dir, "tagged")
    os.makedirs(tagged_dir, exist_ok=True)

    stem = os.path.splitext(os.path.basename(csv_path))[0]
    if case_name:
        return os.path.join(tagged_dir, f"{stem}_{case_name}_tagged.csv")
    else:
        return os.path.join(tagged_dir, f"{stem}_tagged.csv")


# ============================================================
# 4. 시간 / 상태 / AREA (기존 RECmd 로직 유지)
# ============================================================

def time_tag(ts):
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(ts.split(".")[0])
    except Exception:
        return None

    if t >= NOW - timedelta(days=1):
        return "TIME_RECENT"
    if t >= NOW - timedelta(days=7):
        return "TIME_WEEK"
    if t >= NOW - timedelta(days=30):
        return "TIME_MONTH"
    return "TIME_OLD"


def state_tag(deleted_val):
    if str(deleted_val).lower() in ("true", "1"):
        return "STATE_DELETED"
    return "STATE_ACTIVE"


def extract_area(path_str: str):
    if not path_str:
        return None
    p = path_str.lower()

    if "\\users\\" in p and "\\desktop\\" in p:
        return "AREA_USER_DESKTOP"
    if "\\users\\" in p and "\\downloads\\" in p:
        return "AREA_USER_DOWNLOADS"
    if "\\appdata\\local\\" in p:
        return "AREA_APPDATA_LOCAL"
    if "\\appdata\\roaming\\" in p:
        return "AREA_APPDATA_ROAMING"
    if "\\program files" in p:
        return "AREA_PROGRAMFILES"
    if "\\programdata\\" in p:
        return "AREA_PROGRAMDATA"
    if p.startswith("c:\\windows"):
        return "AREA_WINDOWS"
    if re.match(r"^[d-z]:\\", p):
        return "AREA_EXTERNAL_DRIVE"
    return None


# ============================================================
# 5. RECmd CSV 스트리밍 태깅
# ============================================================

def normalize_recmd_csv(csv_path: str):
    case_name = get_kape_child_folder_name(csv_path)
    out_path = get_tagged_output_path(csv_path, case_name)

    with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as fin, \
         open(out_path, "w", encoding="utf-8-sig", newline="") as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(
            fout,
            fieldnames=["Type", "LastWriteTimestamp", "description", "Tags"]
        )
        writer.writeheader()

        for row in reader:
            tags = [
                "ARTIFACT_REGISTRY",
                "FORMAT_REGISTRY",
                "EVENT_MODIFY",
                state_tag(row.get("Deleted")),
            ]

            t = time_tag(row.get("LastWriteTimestamp"))
            if t:
                tags.append(t)

            for col in ("ValueName", "ValueData"):
                area = extract_area(row.get(col, ""))
                if area:
                    tags.append(area)
                    break

            desc_parts = []
            for k in ("KeyPath", "ValueName", "ValueData"):
                v = row.get(k)
                if v:
                    desc_parts.append(f"{k}: {v}")

            writer.writerow({
                "Type": "REGISTRY",
                "LastWriteTimestamp": row.get("LastWriteTimestamp"),
                "description": " | ".join(desc_parts),
                "Tags": " | ".join(dict.fromkeys(tags))
            })

    print(f"[+] Tagged RECmd CSV saved: {out_path}")


# ============================================================
# 6. 엔트리 포인트
# ============================================================

if __name__ == "__main__":
    csvs = find_recmd_csvs()
    if not csvs:
        print("[!] RECmd CSV not found.")
        exit(0)

    for csv_path in csvs:
        normalize_recmd_csv(csv_path)
