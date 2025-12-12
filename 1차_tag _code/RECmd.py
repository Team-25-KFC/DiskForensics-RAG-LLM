import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional

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
# RECmd Tagger
# ============================================================

class RECmdTagger:
    """
    RECmd Batch CSV -> 공통 포맷(Type / LastWriteTimestamp / description / Tags)로 축소 후 JSONL 저장
    """

    def __init__(self):
        self.now = datetime.now()
        self.one_day_ago = self.now - timedelta(days=1)
        self.one_week_ago = self.now - timedelta(days=7)
        self.one_month_ago = self.now - timedelta(days=30)

        self.suspicious_patterns = [
            r"crack", r"keygen", r"payload", r"backdoor", r"mimikatz",
            r"psexec", r"procdump", r"dump", r"inject", r"exploit",
            r"bypass", r"elevated", r"hacktool", r"kali", r"metasploit",
        ]

        self.suspicious_path_patterns = [
            r"\\users\\public\\",
            r"\\users\\.+\\appdata\\local\\temp\\",
            r"\\users\\.+\\appdata\\roaming\\",
            r"\\programdata\\",
            r"\\windows\\temp\\",
        ]

    # ---------- 공통 유틸 ----------

    def get_time_tag(self, ts_value):
        if ts_value is None or pd.isna(ts_value) or ts_value == "":
            return None
        try:
            ts = pd.to_datetime(ts_value)
        except Exception:
            return None

        if ts >= self.one_day_ago:
            return "TIME_RECENT"
        if ts >= self.one_week_ago:
            return "TIME_WEEK"
        if ts >= self.one_month_ago:
            return "TIME_MONTH"
        return "TIME_OLD"

    def extract_timestamp(self, row):
        cand_cols = ["LastWriteTimestamp", "LastWriteTime", "LastWrite", "LastWriteTimeUTC"]
        for c in cand_cols:
            if c in row.index:
                return row[c]
        return None

    def build_description(self, row, fields=None):
        if fields is None:
            fields = ["KeyPath", "ValueName", "ValueType", "ValueData", "Deleted", "Recursive"]

        parts = []
        for col in fields:
            if col in row.index:
                val = row[col]
                if pd.notna(val) and str(val) != "":
                    parts.append(f"{col} : {val}")
        return " | ".join(parts)

    def has_suspicious_text(self, text):
        if pd.isna(text) or text == "":
            return False
        s = str(text).lower()
        return any(re.search(p, s) for p in self.suspicious_patterns)

    def get_sec_exec_and_script_tags(self, row):
        tags = []
        valuedata = str(row.get("ValueData", "") or "").lower()

        if re.search(r"\.(exe|dll|sys|scr)(\s|$)", valuedata):
            tags.append("SEC_EXECUTABLE")
        if re.search(r"\.(ps1|bat|cmd|vbs|js)(\s|$)", valuedata):
            tags.append("SEC_SCRIPT")
        return tags

    def get_sec_suspicious_path_tags(self, row):
        tags = []
        valuedata = str(row.get("ValueData", "") or "").lower()
        keypath = str(row.get("KeyPath", "") or "").lower()
        target = valuedata + " " + keypath

        if not re.search(r"[a-z]:\\\\", target) and "\\\\" not in target:
            return tags

        for pat in self.suspicious_path_patterns:
            if re.search(pat, target):
                tags.append("SEC_SUSPICIOUS_PATH")
                break
        return tags

    def get_state_tags(self, row):
        tags = []
        deleted_val = row.get("Deleted", "")
        if str(deleted_val).strip().lower() in ["true", "1", "yes"]:
            tags.append("STATE_DELETED")
        return tags

    def normalize_tags(self, tags):
        tags = list(dict.fromkeys(tags))

        time_tags = [t for t in tags if t.startswith("TIME_")]
        if len(time_tags) <= 1:
            return tags

        priority = ["TIME_RECENT", "TIME_WEEK", "TIME_MONTH", "TIME_OLD"]
        chosen = next((p for p in priority if p in time_tags), None)

        tags = [t for t in tags if not t.startswith("TIME_")]
        if chosen:
            tags.append(chosen)
        return tags

    # ---------- Type 분류 ----------

    def get_record_type(self, filename: str, row: Optional[dict] = None) -> str:
        fn = filename.lower()

        if "basicsysteminfo" in fn:
            return "REG_BASIC_SYSTEM_INFO"
        if "installedsoftware" in fn:
            return "REG_INSTALLED_SOFTWARE"
        if "registryaseps" in fn:
            return "REG_ASEP_REGISTRY"
        if "softwareaseps" in fn:
            return "REG_ASEP_SOFTWARE"
        if "softwareclassesaseps" in fn:
            return "REG_ASEP_SOFTWARE_CLASSES"
        if "softwarewow6432aseps" in fn:
            return "REG_ASEP_SOFTWARE_WOW6432"
        if "systemaseps" in fn:
            return "REG_ASEP_SYSTEM"
        if "userclassesaseps" in fn:
            return "REG_ASEP_USER_CLASSES"
        if "useractivity" in fn:
            return "REG_USER_ACTIVITY"

        if "dfirbatch" in fn:
            if row:
                cat = str(row.get("Category", "")).lower()
                hive = str(row.get("HiveType", "")).lower()

                if hive == "sam":
                    return "REG_HIVE_SAM"
                if hive == "security":
                    return "REG_HIVE_SECURITY"
                if hive == "software":
                    return "REG_HIVE_SOFTWARE"
                if hive == "system":
                    return "REG_HIVE_SYSTEM"
                if "user accounts" in cat:
                    return "REG_USER_ACCOUNTS"

            return "REG_DFIRBATCH"

        if row:
            keypath = str(row.get("KeyPath", "")).lower()
            if keypath.startswith("root\\sam"):
                return "REG_HIVE_SAM"
            if keypath.startswith("root\\security"):
                return "REG_HIVE_SECURITY"
            if keypath.startswith("root\\software"):
                return "REG_HIVE_SOFTWARE"
            if keypath.startswith("root\\system"):
                return "REG_HIVE_SYSTEM"

        return "REG_UNKNOWN"

    # ---------- 태깅 함수들 ----------

    def tag_basic_system_info(self, row):
        tags = ["ARTIFACT_REGISTRY", "FORMAT_REGISTRY"]

        ts_val = self.extract_timestamp(row)
        t_tag = self.get_time_tag(ts_val)
        if t_tag:
            tags.append(t_tag)

        valuename = str(row.get("ValueName", "")).lower()
        keypath = str(row.get("KeyPath", "")).lower()

        if "productid" in valuename:
            tags.append("SYSTEM_PRODUCT_ID")
        if "productname" in valuename:
            tags.append("SYSTEM_PRODUCT_NAME")
        if "currentversion" in keypath:
            tags.append("SYSTEM_VERSION_INFO")

        valuedata = row.get("ValueData", "")
        if self.has_suspicious_text(valuedata):
            tags.append("SEC_SUSPICIOUS_NAME")

        tags.extend(self.get_state_tags(row))
        tags = self.normalize_tags(tags)
        return " | ".join(tags)

    def tag_installed_software(self, row):
        tags = ["ARTIFACT_REGISTRY", "FORMAT_REGISTRY"]

        ts_val = self.extract_timestamp(row)
        t_tag = self.get_time_tag(ts_val)
        if t_tag:
            tags.append(t_tag)

        valuedata = row.get("ValueData", "")
        keypath = str(row.get("KeyPath", "")).lower()

        if self.has_suspicious_text(valuedata) or self.has_suspicious_text(keypath):
            tags.append("SEC_SUSPICIOUS_NAME")

        tags.extend(self.get_sec_exec_and_script_tags(row))
        tags.extend(self.get_sec_suspicious_path_tags(row))
        tags.extend(self.get_state_tags(row))

        tags = self.normalize_tags(tags)
        return " | ".join(tags)

    def tag_registry_aseps(self, row):
        tags = ["ARTIFACT_REGISTRY", "FORMAT_REGISTRY", "SEC_PERSISTENCE_REGISTRY"]

        ts_val = self.extract_timestamp(row)
        t_tag = self.get_time_tag(ts_val)
        if t_tag:
            tags.append(t_tag)

        valuedata = row.get("ValueData", "")
        if self.has_suspicious_text(valuedata):
            tags.append("SEC_SUSPICIOUS_NAME")

        tags.extend(self.get_sec_exec_and_script_tags(row))
        tags.extend(self.get_sec_suspicious_path_tags(row))
        tags.extend(self.get_state_tags(row))

        tags = self.normalize_tags(tags)
        return " | ".join(tags)

    def tag_software_aseps(self, row):
        return self.tag_registry_aseps(row)

    def tag_software_classes_aseps(self, row):
        return self.tag_registry_aseps(row)

    def tag_software_wow6432_aseps(self, row):
        return self.tag_registry_aseps(row)

    def tag_system_aseps(self, row):
        return self.tag_registry_aseps(row)

    def tag_user_classes_aseps(self, row):
        return self.tag_registry_aseps(row)

    def tag_user_activity(self, row):
        tags = ["ARTIFACT_REGISTRY", "FORMAT_REGISTRY"]

        ts_val = self.extract_timestamp(row)
        t_tag = self.get_time_tag(ts_val)
        if t_tag:
            tags.append(t_tag)

        valuedata = row.get("ValueData", "")
        if self.has_suspicious_text(valuedata):
            tags.append("SEC_SUSPICIOUS_NAME")

        tags.extend(self.get_sec_exec_and_script_tags(row))
        tags.extend(self.get_sec_suspicious_path_tags(row))
        tags.extend(self.get_state_tags(row))

        tags = self.normalize_tags(tags)
        return " | ".join(tags)

    def tag_default(self, row):
        tags = ["ARTIFACT_REGISTRY", "FORMAT_REGISTRY"]

        ts_val = self.extract_timestamp(row)
        t_tag = self.get_time_tag(ts_val)
        if t_tag:
            tags.append(t_tag)

        tags.extend(self.get_sec_exec_and_script_tags(row))
        tags.extend(self.get_sec_suspicious_path_tags(row))
        tags.extend(self.get_state_tags(row))

        tags = self.normalize_tags(tags)
        return " | ".join(tags)

    # ---------- 메인 처리 ----------

    def process_csv(self, csv_path: Path, output_dir: Optional[Path] = None):
        csv_path = Path(csv_path)
        filename = csv_path.name

        df = pd.read_csv(csv_path)

        # 파일명 기반으로 태깅 함수 선택
        if "BasicSystemInfo" in filename:
            tag_func = self.tag_basic_system_info
        elif "InstalledSoftware" in filename:
            tag_func = self.tag_installed_software
        elif "RegistryASEPs" in filename:
            tag_func = self.tag_registry_aseps
        elif "SoftwareASEPs" in filename:
            tag_func = self.tag_software_aseps
        elif "SoftwareClassesASEPs" in filename:
            tag_func = self.tag_software_classes_aseps
        elif "SoftwareWoW6432ASEPs" in filename:
            tag_func = self.tag_software_wow6432_aseps
        elif "SystemASEPs" in filename:
            tag_func = self.tag_system_aseps
        elif "UserClassesASEPs" in filename:
            tag_func = self.tag_user_classes_aseps
        elif "UserActivity" in filename:
            tag_func = self.tag_user_activity
        else:
            tag_func = self.tag_default

        base_type = self.get_record_type(filename)

        out_rows = []
        for _, row in df.iterrows():
            ts_val = self.extract_timestamp(row)
            desc = self.build_description(row)
            tags = tag_func(row)

            out_rows.append(
                {
                    "Type": base_type,
                    "LastWriteTimestamp": ts_val,
                    "description": desc,
                    "Tags": tags,
                }
            )

        out_df = pd.DataFrame(out_rows)

        if output_dir is None:
            jsonl_out = csv_path.with_name(csv_path.stem + "_tagged.jsonl")
        else:
            output_dir.mkdir(parents=True, exist_ok=True)
            jsonl_out = ensure_unique_output_path(output_dir / (csv_path.stem + "_tagged.jsonl"))

        out_df.to_json(jsonl_out, orient="records", lines=True, force_ascii=False)
        return str(jsonl_out), len(out_rows)


# ============================================================
# 실행 (D~Z 스캔)
# ============================================================

if __name__ == "__main__":
    tagger = RECmdTagger()
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs():
        out_dir = drive_root / "tagged" / case_name / "RECmd"
        out_dir.mkdir(parents=True, exist_ok=True)

        csv_files = [
            p for p in case_dir.rglob("*RECmd_Batch_*.csv")
            if "_tagged" not in p.name.lower()
        ]

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | RECmd {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
                jsonl_out, row_count = tagger.process_csv(csv_path, out_dir)
                print(f"  ✓ 완료: {jsonl_out} ({row_count:,}행)")
                total += 1
            except Exception as e:
                print(f"  ✗ 오류: {e}")

    print("\n=== RECmd done:", total, "===")
