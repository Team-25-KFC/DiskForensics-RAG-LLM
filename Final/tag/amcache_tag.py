import pandas as pd
import os
import re
from datetime import datetime, timedelta
import platform
import win32api

# --- 1. 전역 설정 ---

ARTIFACT_TAG = "ARTIFACT_AMCACHE"

NOW = datetime.now()
TIME_RECENT = NOW - timedelta(days=1)
TIME_WEEK = NOW - timedelta(days=7)
TIME_MONTH = NOW - timedelta(days=30)

AREA_PATTERNS = [
    ("AREA_SYSTEM32", r"(?:C:)?\\Windows\\System32|(?:C:)?\\Windows\\SysWOW64"),
    ("AREA_WINDOWS", r"(?:C:)?\\Windows(?!\\System32|\\SysWOW64|\\Temp)"),
    ("AREA_USER_DESKTOP", r"\\Users\\[^\\]*\\Desktop"),
    ("AREA_USER_DOCUMENTS", r"\\Users\\[^\\]*\\Documents"),
    ("AREA_USER_DOWNLOADS", r"\\Users\\[^\\]*\\Downloads"),
    ("AREA_USER_RECENT", r"\\Users\\[^\\]*\\Recent"),
    ("AREA_APPDATA_ROAMING", r"\\Users\\[^\\]*\\AppData\\Roaming"),
    ("AREA_APPDATA_LOCAL", r"\\Users\\[^\\]*\\AppData\\Local"),
    ("AREA_PROGRAMFILES", r"(?:C:)?\\Program Files(?: \\(x86\\))?"),
    ("AREA_PROGRAMDATA", r"(?:C:)?\\ProgramData"),
    ("AREA_TEMP", r"\\Temp\\"),
    ("AREA_STARTUP", r"\\Start Menu\\Programs\\Startup"),
]

CSV_FILENAMES = {
    "Amcache_AssociatedFileEntries": "Amcache_AssociatedFileEntries",
    "Amcache_DeviceContainers": "Amcache_DeviceContainers",
    "Amcache_DevicePnps": "Amcache_DevicePnps",
    "Amcache_DriveBinaries": "Amcache_DriveBinaries",
    "Amcache_DriverPackages": "Amcache_DriverPackages",
    "Amcache_ProgramEntries": "Amcache_ProgramEntries",
    "Amcache_ShortCuts": "Amcache_ShortCuts",
    "Amcache_UnassociatedFileEntries": "Amcache_UnassociatedFileEntries"
}

COLUMNS_TO_DROP = {
    "Amcache_AssociatedFileEntries": ["IsOsComponent", "LongPathHash", "BinaryType", "IsPeFile", "Usn", "BinFileVersion", "BinProductVersion", "ProgramId"],
    "Amcache_DeviceContainers": ["ModelId"],
    "Amcache_DevicePnps": ["Compid", "DriverPackageStrongName", "Inf", "InstallState", "MatchingId", "ProblemCode", "Stackid", "Service", "ParentId", "ContainerId"],
    "Amcache_DriveBinaries": ["DriverInBox", "DriverIsKernelMode", "DriverSigned", "DriverCheckSum", "DriverId", "DriverPackageStrongName", "DriverType", "WdfVersion", "KeyLastWriteTimestamp"],
    "Amcache_DriverPackages": ["DriverInBox", "SubmissionId"],
    "Amcache_ProgramEntries": ["BundleManifestPath", "HiddenArp", "InboxModernApp", "ManifestPath", "MsiPackageCode", "MsiProductCode", "ProgramInstanceId", "RegistryKeyPath", "RootDirPath", "Type", "Source", "StoreAppType"],
    "Amcache_ShortCuts": ["KeyLastWriteTimestamp"],
    "Amcache_UnassociatedFileEntries": ["IsOsComponent", "LongPathHash", "BinaryType", "IsPeFile", "Usn", "BinFileVersion", "BinProductVersion", "ProgramId"],
}

SUSPICIOUS_PATTERNS = [
    r'mimikatz', r'psexec', r'procdump', r'lazagne', r'bloodhound', r'sharphound',
    r'rubeus', r'certutil', r'bitsadmin', r'crack', r'keygen',
    r'backdoor', r'payload', r'ransomware', r'cryptolocker',
    r'wannacry', r'emotet', r'cobalt', r'meterpreter'
]

# --- 2. 외장 드라이브 검색 ---

def find_external_drive_and_kape_output():
    """외장 드라이브와 KAPE Output 폴더 찾기"""
    if platform.system() != "Windows":
        print("🚨 오류: 현재 OS는 Windows가 아닙니다.")
        return None, None

    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\x00')[:-1]
    
    for drive in drives:
        try:
            if drive.upper() in ["A:\\", "B:\\", "C:\\"]:
                continue
            
            for item in os.listdir(drive):
                if re.fullmatch(r"kape\s*output", item, re.IGNORECASE):
                    kape_output_path = os.path.join(drive, item)
                    print(f"✅ KAPE Output 폴더 발견: {kape_output_path}")
                    return drive, kape_output_path
        except Exception:
            continue
            
    print("🚨 오류: 외장 드라이브에서 'KAPE Output' 폴더를 찾을 수 없습니다.")
    return None, None

# --- 3. 헬퍼 함수 ---

def get_area_tag_from_path(path_string):
    if pd.isna(path_string) or not path_string:
        return None
    
    path_string = str(path_string).replace('\\', '/').lower()
    
    for tag, pattern in AREA_PATTERNS:
        regex_pattern = pattern.lower().replace('\\', '/')
        if re.search(regex_pattern, path_string):
            return tag
            
    if re.match(r"^[d-z]:", path_string):
        return "AREA_EXTERNAL_DRIVE"

    return None

def parse_and_get_date(filename):
    """파일명에서 날짜 추출 (YYYYMMDDHHMMSS 형식)"""
    match = re.search(r"(\d{14})_", filename)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
        except ValueError:
            return None
    return None

def get_latest_time_tag_and_timestamp(row, time_cols):
    latest_time = None
    latest_tag = None
    
    # 유효한 시간 범위 설정 (1980년 ~ 현재 시간)
    min_valid_time = datetime(1980, 1, 1)
    max_valid_time = datetime.now()
    
    times = []
    for col_name in time_cols:
        time_str = row.get(col_name)
        if pd.notna(time_str):
            try:
                time = datetime.strptime(time_str.split('.')[0].replace('T', ' ').replace('Z', ''), '%Y-%m-%d %H:%M:%S')
                
                # 유효한 시간 범위 체크: 1980년 이후 ~ 현재 시간 이하
                if min_valid_time <= time <= max_valid_time:
                    times.append((col_name, time))
            except Exception:
                pass

    if not times:
        return None, None

    times.sort(key=lambda x: x[1], reverse=True)
    latest_time_info = times[0]
    latest_time = latest_time_info[1]
    col_name = latest_time_info[0]
    
    if 'Access' in col_name or 'Usn' in col_name:
        latest_tag = "TIME_ACCESSED"
    elif 'Create' in col_name or 'Install' in col_name or 'LinkDate' in col_name:
        latest_tag = "TIME_CREATED"
    elif 'Write' in col_name or 'Modified' in col_name or 'Time' in col_name or 'Date' in col_name:
        latest_tag = "TIME_MODIFIED"
    else:
        latest_tag = "TIME_MODIFIED"

    return latest_tag, latest_time

def get_time_range_tag(dt, base_time):
    """base_time 기준으로 dt가 얼마나 오래됐는지 판단"""
    if dt is None or base_time is None:
        return "TIME_OLD"
    
    time_diff = base_time - dt
    
    if time_diff < timedelta(days=0):
        # CSV 시간이 파일명 날짜보다 미래인 경우
        return "TIME_RECENT"
    elif time_diff <= timedelta(days=1):
        return "TIME_RECENT"
    elif time_diff <= timedelta(days=7):
        return "TIME_WEEK"
    elif time_diff <= timedelta(days=30):
        return "TIME_MONTH"
    else:
        return "TIME_OLD"

def check_suspicious_file_name(row, artifact_name):
    tags = []
    
    if artifact_name in ["Amcache_AssociatedFileEntries", "Amcache_UnassociatedFileEntries"]:
        name = str(row.get('Name', '')).lower()
        
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, name):
                tags.append("SEC_SUSPICIOUS_NAME")
                break
    
    return tags

def analyze_program_entries(row):
    tags = []
    
    hidden_arp = row.get('HiddenArp')
    if pd.notna(hidden_arp) and str(hidden_arp).lower() in ['true', '1']:
        tags.append("SEC_HIDDEN_PROGRAM")
    
    uninstall_str = row.get('UninstallString')
    if pd.isna(uninstall_str) or str(uninstall_str).strip() == '':
        tags.append("SEC_NO_UNINSTALL")
    
    inbox_modern = row.get('InboxModernApp')
    if pd.notna(inbox_modern) and str(inbox_modern).lower() in ['false', '0']:
        tags.append("ACT_EXTERNAL_APP_INSTALL")
    
    manifest_path = row.get('ManifestPath')
    if pd.notna(manifest_path) and manifest_path:
        tags.append("ARTIFACT_STORE_APP")
    
    return tags

def analyze_device_containers(row):
    tags = []
    
    if 'IsActive' in row.index and pd.notna(row['IsActive']):
        is_active_val = str(row['IsActive']).lower()
        if is_active_val in ['true', '1']:
            tags.append("STATE_ACTIVE")
        else:
            tags.append("STATE_INACTIVE")
    
    if 'IsConnected' in row.index and pd.notna(row['IsConnected']):
        is_connected_val = str(row['IsConnected']).lower()
        if is_connected_val in ['true', '1']:
            tags.append("STATE_CONNECTED")
    
    if 'IsNetworked' in row.index and pd.notna(row['IsNetworked']):
        is_networked_val = str(row['IsNetworked']).lower()
        if is_networked_val in ['true', '1']:
            tags.append("AREA_NETWORK_DEVICE")
    
    return tags

def analyze_driver_packages(row):
    tags = []
    
    driver_inbox = row.get('DriverInBox')
    if pd.notna(driver_inbox) and str(driver_inbox).lower() in ['false', '0']:
        tags.append("SEC_EXTERNAL_DRIVER")
        tags.append("ACT_INSTALL")
    
    return tags

def analyze_drive_binaries(row):
    tags = []
    
    driver_signed = row.get('DriverSigned')
    if pd.notna(driver_signed) and str(driver_signed).lower() in ['false', '0']:
        tags.append("SEC_UNSIGNED_DRIVER")
    
    is_kernel_mode = row.get('DriverIsKernelMode')
    if pd.notna(is_kernel_mode) and str(is_kernel_mode).lower() in ['true', '1']:
        tags.append("SEC_KERNEL_MODE_DRIVER")
    
    return tags

def create_description_column(row, original_columns):
    description = []
    for col in original_columns:
        if pd.notna(row.get(col)):
            content = str(row[col]).replace('|', ',')
            description.append(f"{col} : {content}")
    return " | ".join(description)

# --- 4. 메인 처리 함수 ---

def process_amcache_csv(df, artifact_name, time_cols, filename_date):
    """Amcache CSV 처리 및 태깅"""
    
    original_columns = df.columns.tolist()
    
    cols_to_drop = COLUMNS_TO_DROP.get(artifact_name, [])
    df.drop(columns=[col for col in cols_to_drop if col in df.columns], errors='ignore', inplace=True)
    
    current_columns = df.columns.tolist()
    
    df['tag'] = ""
    df['LatestTimestamp'] = pd.NaT
    
    path_col = None
    if artifact_name in ["Amcache_AssociatedFileEntries", "Amcache_UnassociatedFileEntries"] and "FullPath" in df.columns:
        path_col = "FullPath"
    elif "KeyName" in df.columns:
        path_col = "KeyName"

    for index, row in df.iterrows():
        tags = [ARTIFACT_TAG]
        
        if path_col and pd.notna(row[path_col]):
            area_tag = get_area_tag_from_path(row[path_col])
            if area_tag:
                tags.append(area_tag)
        
        if artifact_name in ["Amcache_AssociatedFileEntries", "Amcache_UnassociatedFileEntries"]:
            tags.append("ACT_EXECUTE")
            tags.append("EVENT_EXECUTED")
            tags.extend(check_suspicious_file_name(row, artifact_name))
        
        elif artifact_name == "Amcache_ProgramEntries":
            tags.append("ACT_INSTALL")
            tags.append("EVENT_INSTALLED")
            tags.extend(analyze_program_entries(row))
        
        elif artifact_name == "Amcache_DeviceContainers":
            tags.extend(analyze_device_containers(row))
        
        elif artifact_name == "Amcache_DriverPackages":
            tags.extend(analyze_driver_packages(row))
        
        elif artifact_name == "Amcache_DriveBinaries":
            tags.extend(analyze_drive_binaries(row))
        
        elif artifact_name == "Amcache_DevicePnps":
            tags.append("ACT_INSTALL")
        
        if artifact_name in ["Amcache_AssociatedFileEntries", "Amcache_UnassociatedFileEntries"]:
            if 'FileExtension' in row.index:
                ext = str(row['FileExtension']).lower()
                
                if ext in ['.exe', '.dll', '.sys', '.scr', '.com', '.cpl']:
                    tags.append("SEC_EXECUTABLE")
                    tags.append("FORMAT_EXECUTABLE")
                elif ext in ['.ps1', '.bat', '.vbs', '.js', '.py', '.cmd']:
                    tags.append("SEC_SCRIPT")
                    tags.append("FORMAT_SCRIPT")
                elif ext in ['.lnk']:
                    tags.append("ARTIFACT_LNK")
                    tags.append("FORMAT_SHORTCUT")
        
        # ✅ CSV 시간 컬럼에서 가장 최신 시간 추출 (비정상 시간 필터링)
        time_tag, latest_dt = get_latest_time_tag_and_timestamp(row, time_cols)
        
        # ✅ LastWriteTimestamp와 TIME_RECENT/WEEK/MONTH: CSV 시간을 파일명 날짜 기준으로 비교
        if latest_dt:
            tags.append(time_tag)
            tags.append(get_time_range_tag(latest_dt, filename_date))
            df.loc[index, 'LatestTimestamp'] = latest_dt
            
            if time_tag == "TIME_MODIFIED":
                tags.append("EVENT_MODIFY")

        tags = sorted(list(set(tags)))
        df.loc[index, 'tag'] = " | ".join(tags)
        
    df['type'] = artifact_name.replace("Amcache_", "AMCACHE_")
    df['LastWriteTimestamp'] = df['LatestTimestamp'].dt.strftime('%Y-%m-%d %H:%M:%S.%f').str[:-3]
    
    cols_for_description = [col for col in current_columns if col not in ['tag', 'LatestTimestamp']]
    df['description'] = df.apply(lambda row: create_description_column(row, cols_for_description), axis=1)

    final_df = df[['type', 'LastWriteTimestamp', 'description', 'tag']].copy()
    
    return final_df

# --- 5. 실행 함수 ---

def main_processing_logic(artifact_key, time_cols):
    """개별 CSV 파일 처리"""
    
    drive_path, kape_output_path = find_external_drive_and_kape_output()
    if not kape_output_path:
        return
    
    csv_pattern = CSV_FILENAMES.get(artifact_key)
    if not csv_pattern:
        print(f"🚨 오류: {artifact_key}에 해당하는 패턴을 찾을 수 없습니다.")
        return

    # 파일명에 패턴이 포함된 모든 CSV 찾기
    matched_files = []
    for root, _, files in os.walk(kape_output_path):
        for file in files:
            if csv_pattern in file and file.endswith('.csv'):
                matched_files.append((root, file))
    
    if not matched_files:
        print(f"⚠️ 경고: '{csv_pattern}'이 포함된 CSV 파일을 찾을 수 없습니다.")
        return

    print(f"📋 '{csv_pattern}' 패턴으로 {len(matched_files)}개 파일 발견")

    tagged_dir = os.path.join(drive_path, "tagged")
    os.makedirs(tagged_dir, exist_ok=True)
    
    # 모든 매칭 파일 처리
    for root, csv_filename in matched_files:
        input_filepath = os.path.join(root, csv_filename)
        
        # 폴더명 추출
        relative_path = os.path.relpath(root, kape_output_path)
        folder_prefix = relative_path.replace(os.sep, '_').replace(' ', '_')
        
        # 출력 파일명
        output_filename = f"{folder_prefix}_tagged_{csv_filename}"
        output_filepath = os.path.join(tagged_dir, output_filename)
        
        print(f"\n📂 파일 처리 시작: {input_filepath}")
        print(f"  ℹ️  폴더 경로: {relative_path}")
        
        try:
            df = pd.read_csv(input_filepath, encoding='utf-8', on_bad_lines='skip')
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(input_filepath, encoding='cp949', on_bad_lines='skip')
            except Exception as e:
                print(f"❌ {csv_filename} 로드 실패: {e}")
                continue
        except Exception as e:
            print(f"❌ {csv_filename} 로드 실패: {e}")
            continue

        # ✅ 파일명에서 날짜 추출
        filename_date = parse_and_get_date(csv_filename)
        
        final_df = process_amcache_csv(df, artifact_key, time_cols, filename_date)
        
        final_df.to_csv(output_filepath, index=False, encoding='utf-8')
        print(f"✅ 처리 완료: {output_filepath}")

def run_all_amcache_processing():
    """모든 Amcache CSV 파일 처리"""
    
    processing_tasks = [
        ("Amcache_AssociatedFileEntries", ["FileKeyLastWriteTimestamp", "LinkDate"]),
        ("Amcache_DeviceContainers", ["KeyLastWriteTimestamp"]),
        ("Amcache_DevicePnps", ["KeyLastWriteTimestamp", "DriverVerDate"]),
        ("Amcache_DriveBinaries", ["DriverTimeStamp", "DriverLastWriteTime"]),
        ("Amcache_DriverPackages", ["KeyLastWriteTimestamp", "Date"]),
        ("Amcache_ProgramEntries", ["KeyLastWriteTimestamp", "InstallDateArpLastModified", "InstallDate", "InstallDateMsi", "InstallDateFromLinkFile"]),
        ("Amcache_ShortCuts", ["KeyLastWriteTimestamp"]),
        ("Amcache_UnassociatedFileEntries", ["FileKeyLastWriteTimestamp", "LinkDate"]),
    ]
    
    for artifact_key, time_cols in processing_tasks:
        main_processing_logic(artifact_key, time_cols)

if __name__ == "__main__":
    print("--- Amcache 태깅 시작 (총 8종) ---")
    run_all_amcache_processing()
    print("\n--- 모든 처리 완료 ---")