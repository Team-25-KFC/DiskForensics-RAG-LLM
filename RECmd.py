import pandas as pd
import re
from datetime import datetime, timedelta
from pathlib import Path


class RECmdTagger:
    """
    RECmd Batch CSV를 1차 자동 태깅해서
    공통 포맷(Type / LastWriteTimestamp / description / Tags)으로 축소 + JSONL 저장

    - Type: REG_* (파일 단위 아티팩트 그룹)
    - description: KeyPath / ValueName / ValueType / ValueData / Deleted / Recursive
    - Tags: ARTIFACT_REGISTRY, FORMAT_REGISTRY, SEC_*, TIME_*, STATE_*
    """

    def __init__(self):
        # 시간 기준
        self.now = datetime.now()
        self.one_day_ago = self.now - timedelta(days=1)
        self.one_week_ago = self.now - timedelta(days=7)
        self.one_month_ago = self.now - timedelta(days=30)

        # SEC_SUSPICIOUS_NAME에 쓰는 문자열 패턴
        self.suspicious_patterns = [
            r"crack",
            r"keygen",
            r"payload",
            r"backdoor",
            r"mimikatz",
            r"psexec",
            r"procdump",
            r"dump",
            r"inject",
            r"exploit",
            r"bypass",
            r"elevated",
            r"hacktool",
            r"kali",
            r"metasploit",
        ]

        # SEC_SUSPICIOUS_PATH용 경로 패턴
        self.suspicious_path_patterns = [
            r"\\users\\public\\",
            r"\\users\\.+\\appdata\\local\\temp\\",
            r"\\users\\.+\\appdata\\roaming\\",
            r"\\programdata\\",
            r"\\windows\\temp\\",
        ]

    # ---------- 공통 유틸 ----------

    def get_time_tag(self, ts_value):
        """LastWriteTimestamp 계열 값을 기준으로 TIME_ 태그 반환 (항상 0개 또는 1개)"""
        if ts_value is None or pd.isna(ts_value) or ts_value == "":
            return None

        try:
            ts = pd.to_datetime(ts_value)
        except Exception:
            return None

        if ts >= self.one_day_ago:
            return "TIME_RECENT"
        elif ts >= self.one_week_ago:
            return "TIME_WEEK"
        elif ts >= self.one_month_ago:
            return "TIME_MONTH"
        else:
            return "TIME_OLD"

    def extract_timestamp(self, row):
        """RECmd CSV에서 LastWriteTimestamp 계열 컬럼을 유연하게 찾는다"""
        cand_cols = [
            "LastWriteTimestamp",
            "LastWriteTime",
            "LastWrite",
            "LastWriteTimeUTC",
        ]
        for c in cand_cols:
            if c in row.index:
                return row[c]
        return None

    def build_description(self, row, fields=None):
        """
        여러 컬럼을 'Key : Value | Key2 : Value2' 형태 문자열로 합침
        fields가 None이면 기본 레지스트리 필드 세트를 사용
        """
        if fields is None:
            fields = [
                "KeyPath",
                "ValueName",
                "ValueType",
                "ValueData",
                "Deleted",
                "Recursive",
            ]

        parts = []
        for col in fields:
            if col in row.index:
                val = row[col]
                if pd.notna(val) and str(val) != "":
                    parts.append(f"{col} : {val}")
        return " | ".join(parts)

    def has_suspicious_text(self, text):
        """의심 이름(문자열) 패턴: SEC_SUSPICIOUS_NAME 전용"""
        if pd.isna(text) or text == "":
            return False
        s = str(text).lower()
        for p in self.suspicious_patterns:
            if re.search(p, s):
                return True
        return False

    def get_sec_exec_and_script_tags(self, row):
        """ValueData 기준으로 SEC_EXECUTABLE / SEC_SCRIPT 태깅"""
        tags = []
        valuedata = str(row.get("ValueData", "") or "").lower()

        # 실행 파일
        if re.search(r"\.(exe|dll|sys|scr)(\s|$)", valuedata):
            tags.append("SEC_EXECUTABLE")

        # 스크립트
        if re.search(r"\.(ps1|bat|cmd|vbs|js)(\s|$)", valuedata):
            tags.append("SEC_SCRIPT")

        return tags

    def get_sec_suspicious_path_tags(self, row):
        """경로 기반: SEC_SUSPICIOUS_PATH (실제로 경로처럼 보일 때만)"""
        tags = []
        valuedata = str(row.get("ValueData", "") or "").lower()
        keypath = str(row.get("KeyPath", "") or "").lower()

        target = valuedata + " " + keypath

        # 경로처럼 안 보이면 스킵
        if not re.search(r"[a-z]:\\\\", target) and "\\\\" not in target:
            return tags

        for pat in self.suspicious_path_patterns:
            if re.search(pat, target):
                tags.append("SEC_SUSPICIOUS_PATH")
                break

        return tags

    def get_state_tags(self, row):
        """Deleted 여부 기반 STATE_DELETED"""
        tags = []
        deleted_val = row.get("Deleted", "")

        if str(deleted_val).strip().lower() in ["true", "1", "yes"]:
            tags.append("STATE_DELETED")

        return tags

    def normalize_tags(self, tags):
        """
        - 중복 제거 (순서 유지)
        - TIME_ 계열 태그는 최대 1개만 남기기
        """
        tags = list(dict.fromkeys(tags))

        time_tags = [t for t in tags if t.startswith("TIME_")]
        if len(time_tags) <= 1:
            return tags

        priority = ["TIME_RECENT", "TIME_WEEK", "TIME_MONTH", "TIME_OLD"]
        chosen = None
        for p in priority:
            if p in time_tags:
                chosen = p
                break

        tags = [t for t in tags if not t.startswith("TIME_")]
        if chosen:
            tags.append(chosen)

        return tags

    def get_record_type(self, filename: str) -> str:
        """파일명 기준으로 이 CSV 행들의 Type(아티팩트 그룹)을 결정"""
        if "BasicSystemInfo" in filename:
            return "REG_BASIC_SYSTEM_INFO"
        elif "InstalledSoftware" in filename:
            return "REG_INSTALLED_SOFTWARE"
        elif "RegistryASEPs" in filename:
            return "REG_ASEP_REGISTRY"
        elif "SoftwareASEPs" in filename:
            return "REG_ASEP_SOFTWARE"
        elif "SoftwareClassesASEPs" in filename:
            return "REG_ASEP_SOFTWARE_CLASSES"
        elif "SoftwareWoW6432ASEPs" in filename:
            return "REG_ASEP_SOFTWARE_WOW6432"
        elif "SystemASEPs" in filename:
            return "REG_ASEP_SYSTEM"
        elif "UserClassesASEPs" in filename:
            return "REG_ASEP_USER_CLASSES"
        elif "UserActivity" in filename:
            return "REG_USER_ACTIVITY"
        else:
            return "REG_UNKNOWN"

    # ---------- 태그 함수들 ----------

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
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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

    def tag_software_classes_aseps(self, row):
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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

    def tag_software_wow6432_aseps(self, row):
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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

    def tag_system_aseps(self, row):
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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

    def tag_user_classes_aseps(self, row):
        tags = [
            "ARTIFACT_REGISTRY",
            "FORMAT_REGISTRY",
            "SEC_PERSISTENCE_REGISTRY",
        ]

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
        """어느 카테고리에도 안 들어가는 RECmd CSV용 기본 태그"""
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

    def process_csv(self, csv_path):
        """
        RECmd Batch CSV 하나를 읽어서
        Type / LastWriteTimestamp / description / Tags 만 남긴 JSONL로 변환
        """
        csv_path = Path(csv_path)
        filename = csv_path.name

        df = pd.read_csv(csv_path)

        # 어떤 태깅 함수를 쓸지 파일명으로 결정
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

        out_rows = []

        # 이 CSV 전체에 공통으로 쓸 Type (아티팩트 그룹)
        base_type = self.get_record_type(filename)

        for _, row in df.iterrows():
            type_val = base_type

            ts_val = self.extract_timestamp(row)
            desc = self.build_description(row)
            tags = tag_func(row)

            out_rows.append(
                {
                    "Type": type_val,
                    "LastWriteTimestamp": ts_val,
                    "description": desc,
                    "Tags": tags,
                }
            )

        out_df = pd.DataFrame(out_rows)

        # JSONL만 생성
        jsonl_out = csv_path.with_name(csv_path.stem + "_tagged.jsonl")
        out_df.to_json(
            jsonl_out,
            orient="records",
            lines=True,
            force_ascii=False,
        )

        return str(jsonl_out), len(out_rows)


# 사용 예시
if __name__ == "__main__":
    from pathlib import Path

    tagger = RECmdTagger()

    # 현재 .py가 있는 디렉터리
    base_dir = Path(__file__).resolve().parent

    # .. / lang_flow
    input_root = base_dir.parent / "여기에 상위폴더 이름!!!!"

    if not input_root.exists():
        print(f"폴더를 찾을 수 없지혁..: {input_root}")
        raise SystemExit(1)

    #  모든 하위폴더에서 RECmd_Batch_*.csv 찾기
    csv_files = [
        p
        for p in input_root.rglob("*RECmd_Batch_*.csv")
        if "_tagged" not in p.name
    ]

    if not csv_files:
        print("처리할 RECmd Batch CSV 파일이 없습니다.")
    else:
        print(f"총 {len(csv_files)}개의 RECmd CSV 파일을 찾았습니다.\n")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
                jsonl_out, row_count = tagger.process_csv(csv_path)
                print(f" JSONL 완료: {jsonl_out} ({row_count:,}개 행)\n")
            except Exception as e:
                print(f" 오류 발생: {csv_path} → {e}\n")

        print("=" * 50)
        print("모든 파일 처리 완료!")
