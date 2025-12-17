import pandas as pd
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
import platform

# Windows 전용 모듈
try:
    import win32api
except ImportError:
    pass

# --- 1. 전역 설정 ---

ARTIFACT_TAG = "ARTIFACT_SRUM"

NOW = datetime.now()
TIME_RECENT_REF = NOW - timedelta(days=1)
TIME_WEEK_REF = NOW - timedelta(days=7)
TIME_MONTH_REF = NOW - timedelta(days=30)

UNNECESSARY_COLUMNS = [
    'Id', 'AppId', 'UserId', 'SidType', 'Sid', 'EntryId', 'AutoIncId',
    'InterfaceLuid', 'L2ProfileFlags', 'L2ProfileId',
    'ExeTimestamp',
    'IsLt', 'ConfigurationHash', 'ChargeLevel', 'CycleCount',
    'DesignedCapacity', 'FullChargedCapacity', 'CsAcTime', 'CsDcTime',
    'CsDischargeTime', 'CsEnergy',
    'Flags'
]

SUSPICIOUS_PATTERNS = [
    r'mimikatz', r'psexec', r'procdump', r'lazagne', r'bloodhound', r'sharphound',
    r'rubeus', r'certutil', r'bitsadmin', r'crack', r'keygen',
    r'backdoor', r'payload', r'ransomware', r'cryptolocker',
    r'wannacry', r'emotet', r'cobalt', r'meterpreter', r'empire', r'covenant'
]

SYSTEM_PATHS = [
    r'\\windows\\system32', r'\\windows\\syswow64'
]

SUSPICIOUS_PATHS = {
    'AREA_TEMP': [
        r'\\appdata\\local\\temp',
        r'\\windows\\temp',
        r'\\temp\\',
        r'^c:\\temp'
    ],
    'AREA_USER_DOWNLOADS': [
        r'\\downloads\\'
    ],
    'AREA_APPDATA_LOCAL': [
        r'\\appdata\\local\\(?!temp)'
    ],
    'AREA_APPDATA_ROAMING': [
        r'\\appdata\\roaming\\'
    ]
}

SCRIPT_EXTENSIONS = ['.ps1', '.bat', '.vbs', '.js', '.cmd', '.wsf', '.hta']

TIME_COLUMNS_BY_TABLE = {
    'AppResourceUseInfo': ['Timestamp'],
    'NetworkUsages': ['Timestamp'],
    'NetworkConnections': ['ConnectStartTime', 'Timestamp'],
    'AppTimelineProvider': ['EndTime', 'Timestamp'],
    'EnergyUsage': ['EventTimestamp', 'Timestamp'],
    'PushNotifications': ['Timestamp'],
    'vfuprov': ['StartTime', 'EndTime', 'Timestamp']
}

CSV_FILENAMES = {
    "SrumECmd_AppResourceUseInfo": "_SrumECmd_AppResourceUseInfo_Output.csv",
    "SrumECmd_vfuprov": "_SrumECmd_vfuprov_Output.csv",
    "SrumECmd_PushNotifications": "_SrumECmd_PushNotifications_Output.csv",
    "SrumECmd_NetworkUsages": "_SrumECmd_NetworkUsages_Output.csv",
    "SrumECmd_NetworkConnections": "_SrumECmd_NetworkConnections_Output.csv",
    "SrumECmd_EnergyUsage": "_SrumECmd_EnergyUsage_Output.csv",
    "SrumECmd_AppTimelineProvider": "_SrumECmd_AppTimelineProvider_Output.csv",
}

class Thresholds:
    RANSOMWARE_WRITE_BYTES = 100 * 1024 * 1024
    RANSOMWARE_WRITE_READ_RATIO = 2
    EXFILTRATION_UPLOAD_BYTES = 50 * 1024 * 1024
    EXFILTRATION_READ_BYTES = 5 * 1024 * 1024 * 1024
    EXFILTRATION_READ_WRITE_RATIO = 0.05
    BULK_DOWNLOAD_BYTES = 100 * 1024 * 1024
    ABNORMAL_UPLOAD_RATIO = 10

# --- 2. 외장 드라이브 검색 함수 ---

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
                # ⭐ 수정: fullmatch 사용으로 정확한 매칭
                if re.fullmatch(r"kape\s*output", item, re.IGNORECASE):
                    kape_output_path = os.path.join(drive, item)
                    print(f"✅ KAPE Output 폴더 발견: {kape_output_path}")
                    return drive, kape_output_path
        except Exception:
            continue
            
    print("🚨 오류: 외장 드라이브에서 'KAPE Output' 폴더를 찾을 수 없습니다.")
    return None, None

# --- 3. 헬퍼 함수 ---

def parse_srum_time(time_str):
    if pd.isna(time_str) or time_str == '':
        return None
    try:
        if len(time_str.split('.')) > 1:
            return datetime.strptime(time_str.split('.')[0], '%Y-%m-%d %H:%M:%S') + \
                   timedelta(microseconds=int(time_str.split('.')[1][:6]))
        else:
            return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None

def _get_latest_timestamp_and_tag(row, table_type):
    time_cols = TIME_COLUMNS_BY_TABLE.get(table_type)
    if not time_cols:
        return None, None
    
    valid_times = []
    for col in time_cols:
        if col in row.index and pd.notna(row[col]) and row[col] != '':
            ts = parse_srum_time(row[col])
            if ts:
                valid_times.append((col, ts))
    
    if not valid_times:
        return None, None
    
    latest_time_info = max(valid_times, key=lambda x: x[1])
    col_name, latest_time = latest_time_info
    
    time_tag = "TIME_MODIFIED"
    if 'Start' in col_name or 'EventTimestamp' in col_name or 'ConnectStartTime' in col_name:
        time_tag = "TIME_CREATED"
    elif 'End' in col_name:
        time_tag = "TIME_CLOSED"

    return latest_time, time_tag

def _get_time_range_tag(dt):
    if dt >= TIME_RECENT_REF:
        return "TIME_RECENT"
    elif dt >= TIME_WEEK_REF:
        return "TIME_WEEK"
    elif dt >= TIME_MONTH_REF:
        return "TIME_MONTH"
    else:
        return "TIME_OLD"

def is_executable(exe_info):
    if pd.isna(exe_info) or exe_info == '':
        return False
    exe_lower = str(exe_info).lower()
    return exe_lower.endswith(('.exe', '.dll', '.scr', '.sys'))

def is_script(exe_info):
    if pd.isna(exe_info) or exe_info == '':
        return False
    exe_lower = str(exe_info).lower()
    return any(exe_lower.endswith(ext) for ext in SCRIPT_EXTENSIONS)

def check_suspicious_exe_name(exe_info):
    if pd.isna(exe_info) or exe_info == '':
        return False
    
    exe_lower = str(exe_info).lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, exe_lower):
            return True
    return False

def check_system_path(exe_info):
    if pd.isna(exe_info) or exe_info == '':
        return False
    
    exe_lower = str(exe_info).lower()
    for pattern in SYSTEM_PATHS:
        if re.search(pattern, exe_lower):
            return True
    return False

def check_suspicious_path(exe_info):
    if pd.isna(exe_info) or exe_info == '':
        return False, []
    
    exe_lower = str(exe_info).lower().replace('\\', '/')
    area_tags = []
    
    is_exec_or_script = is_executable(exe_info) or is_script(exe_info)
    if not is_exec_or_script:
        return False, []
    
    for area_tag, patterns in SUSPICIOUS_PATHS.items():
        for pattern in patterns:
            regex_pattern = pattern.lower().replace('\\', '/')
            if re.search(regex_pattern, exe_lower):
                area_tags.append(area_tag)
                break
    
    is_suspicious = len(area_tags) > 0 and any(
        tag in ['AREA_TEMP', 'AREA_USER_DOWNLOADS'] for tag in area_tags
    )
    
    return is_suspicious, area_tags

def analyze_io_pattern(row):
    tags = []
    
    fg_bytes_read = row.get('ForegroundBytesRead', 0)
    fg_bytes_written = row.get('ForegroundBytesWritten', 0)
    
    try:
        read = float(fg_bytes_read) if pd.notna(fg_bytes_read) and fg_bytes_read != '' else 0
        write = float(fg_bytes_written) if pd.notna(fg_bytes_written) and fg_bytes_written != '' else 0

        if write > Thresholds.RANSOMWARE_WRITE_BYTES and write > read * Thresholds.RANSOMWARE_WRITE_READ_RATIO:
            tags.append("SEC_RANSOMWARE_INDICATOR")
            
        elif read > Thresholds.EXFILTRATION_READ_BYTES:
            if write < read * Thresholds.EXFILTRATION_READ_WRITE_RATIO:
                tags.append("SEC_EXFILTRATION")
    except (ValueError, TypeError):
        pass
    
    return tags

def analyze_network_pattern(row):
    tags = []
    
    bytes_sent = row.get('BytesSent', 0)
    bytes_received = row.get('BytesReceived', 0)
    
    try:
        sent = float(bytes_sent) if pd.notna(bytes_sent) and bytes_sent != '' else 0
        received = float(bytes_received) if pd.notna(bytes_received) and bytes_received != '' else 0
        
        if sent > Thresholds.EXFILTRATION_UPLOAD_BYTES:
            tags.append("SEC_EXFILTRATION_INDICATOR")
            tags.append("ACT_UPLOAD")
        
        if received > 0 and sent / received > Thresholds.ABNORMAL_UPLOAD_RATIO:
            tags.append("SEC_ABNORMAL_UPLOAD_RATIO")
        
        if received > Thresholds.BULK_DOWNLOAD_BYTES:
            tags.append("ACT_DOWNLOAD")
            if sent > 0 and sent < received * 0.1:
                tags.append("SEC_BULK_DOWNLOAD")
    except (ValueError, TypeError, ZeroDivisionError):
        pass
    
    return tags

def analyze_vfuprov_duration(row):
    tags = []
    
    duration = row.get('Duration', 0)
    if pd.notna(duration) and duration != '':
        try:
            duration_sec = int(float(duration))
            
            if duration_sec > 1800:
                tags.append("ACT_LONG_SESSION")
            elif duration_sec < 10:
                tags.append("ACT_SHORT_SESSION")
        except (ValueError, TypeError):
            pass
    
    return tags

def analyze_energy_usage(row):
    tags = []
    
    state_transition = row.get('StateTransition', '')
    if pd.notna(state_transition):
        state_str = str(state_transition).lower()
        
        if 'discharge' in state_str:
            tags.append("STATE_BATTERY_DISCHARGE")
            tags.append("ACT_MOBILE_USAGE")
        elif 'charg' in state_str:
            tags.append("STATE_BATTERY_CHARGE")
    
    return tags

def analyze_push_notifications(row):
    tags = []
    
    notification_type = row.get('NotificationType', '')
    if pd.notna(notification_type):
        notif_str = str(notification_type).lower()
        if 'toast' in notif_str:
            tags.append("EVENT_NOTIFICATION")
    
    payload_size = row.get('PayloadSize', 0)
    try:
        size = float(payload_size) if pd.notna(payload_size) and payload_size != '' else 0
        if size > 10000:
            tags.append("ACT_LARGE_NOTIFICATION")
    except (ValueError, TypeError):
        pass
    
    return tags

def analyze_network_connections(row):
    tags = []
    
    profile_name = row.get('ProfileName', '')
    if pd.notna(profile_name) and profile_name:
        profile_str = str(profile_name).lower()
        
        if 'unknown' in profile_str or 'unidentified' in profile_str:
            tags.append("SEC_UNKNOWN_NETWORK")
        elif 'public' in profile_str:
            tags.append("AREA_PUBLIC_NETWORK")
    
    connected_time = row.get('ConnectedTime', 0)
    try:
        conn_time = float(connected_time) if pd.notna(connected_time) and connected_time != '' else 0
        if conn_time > 0 and conn_time < 10:
            tags.append("SEC_SHORT_CONNECTION")
    except (ValueError, TypeError):
        pass
    
    return tags

def create_description_column(row, current_columns):
    desc_parts = []
    
    excluded_cols = set(UNNECESSARY_COLUMNS + ['Tags', 'LatestTimestamp'])
    
    for col in current_columns:
        if col in excluded_cols:
            continue
        
        value = row.get(col)
        if pd.isna(value) or value == '':
            continue
        
        str_value = str(value).strip()
        if str_value and str_value != '0':
            desc_parts.append(f"{col}: {str_value}")
    
    return " | ".join(desc_parts)

# --- 4. 메인 처리 함수 ---

def process_srum_csv(df, table_type):
    """SRUM CSV 처리 및 태깅"""
    
    original_columns = df.columns.tolist()
    result_rows = []
    
    exe_info_col = "ExeInfo" if "ExeInfo" in df.columns else None

    print(f"  ℹ️  {table_type} 테이블 태깅 시작")
    
    for _, row in df.iterrows():
        tags = [ARTIFACT_TAG]
        
        latest_time, time_tag = _get_latest_timestamp_and_tag(row, table_type)
        last_write_timestamp = ''
        
        if latest_time:
            tags.append(_get_time_range_tag(latest_time))
            tags.append(time_tag)
            last_write_timestamp = latest_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        exe_info = row.get(exe_info_col, '') if exe_info_col else ''
        
        if exe_info_col and exe_info and str(exe_info).strip():
            if is_executable(exe_info):
                tags.append("FORMAT_EXECUTABLE")
                tags.append("SEC_EXECUTABLE")
            elif is_script(exe_info):
                tags.append("FORMAT_SCRIPT")
                tags.append("SEC_SCRIPT")
                
            if check_system_path(exe_info):
                tags.append("AREA_SYSTEM32")
            
            if check_suspicious_exe_name(exe_info):
                tags.append("SEC_SUSPICIOUS_NAME")
            
            is_suspicious_path, area_tags = check_suspicious_path(exe_info)
            tags.extend(area_tags)
            if is_suspicious_path:
                tags.append("SEC_SUSPICIOUS_PATH")
        
        if table_type in ['AppResourceUseInfo', 'AppTimelineProvider']:
            tags.append("ACT_EXECUTE")
        
        elif table_type == 'vfuprov':
            tags.append("ACT_EXECUTE")
            tags.extend(analyze_vfuprov_duration(row))
        
        elif table_type == 'NetworkUsages':
            tags.append("ACT_NETWORK_ACCESS")
            tags.extend(analyze_network_pattern(row))
        
        elif table_type == 'NetworkConnections':
            tags.append("ACT_NETWORK_ACCESS")
            tags.extend(analyze_network_connections(row))
        
        elif table_type == 'PushNotifications':
            tags.append("ACT_NETWORK_ACCESS")
            tags.append("ACT_COMMUNICATION")
            tags.extend(analyze_push_notifications(row))
        
        elif table_type == 'EnergyUsage':
            tags.extend(analyze_energy_usage(row))
        
        if table_type == 'AppResourceUseInfo':
            tags.extend(analyze_io_pattern(row))
        
        description = create_description_column(row, original_columns)
        tags = sorted(list(set(tags)))
        
        result_rows.append({
            'Type': "SRUM_" + table_type,
            'LastWriteTimestamp': last_write_timestamp,
            'Description': description,
            'Tags': " | ".join(tags)
        })
        
    final_df = pd.DataFrame(result_rows)
    print(f"  ℹ️  원본 컬럼: {len(original_columns)}개 → 정제 후: 4개")
    return final_df

# --- 5. 실행 함수 ---

def main_processing_logic(artifact_key):
    """개별 CSV 파일 처리"""
    
    drive_path, kape_output_path = find_external_drive_and_kape_output()
    if not kape_output_path:
        return
    
    table_type = artifact_key.replace("SrumECmd_", "")
    filename_pattern = CSV_FILENAMES.get(artifact_key)
    if not filename_pattern:
        print(f"🚨 오류: {artifact_key}에 해당하는 파일 패턴을 찾을 수 없습니다.")
        return

    search_pattern = r"\d{14}" + re.escape(filename_pattern)
    
    # 모든 매칭 파일 찾기
    matched_files = []
    for root, _, files in os.walk(kape_output_path):
        for file in files:
            if re.match(search_pattern, file):
                matched_files.append((root, file))
    
    if not matched_files:
        print(f"⚠️ 경고: *{filename_pattern} 파일을 찾을 수 없습니다.")
        return

    tagged_dir = Path(drive_path) / "tagged"
    tagged_dir.mkdir(exist_ok=True)
    
    # 모든 매칭 파일 처리
    for root, csv_filename in matched_files:
        input_filepath = os.path.join(root, csv_filename)
        
        # 폴더명 추출
        relative_path = os.path.relpath(root, kape_output_path)
        folder_prefix = relative_path.replace(os.sep, '_').replace(' ', '_')
        
        # 출력 파일명
        output_filename = f"{folder_prefix}_tagged_{csv_filename}"
        output_filepath = tagged_dir / output_filename
        
        print(f"\n📂 파일 처리 시작: {input_filepath}")
        print(f"  ℹ️  폴더 경로: {relative_path}")
        
        try:
            df = pd.read_csv(input_filepath, encoding='utf-8', on_bad_lines='skip', low_memory=False)
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(input_filepath, encoding='cp949', on_bad_lines='skip', low_memory=False)
            except Exception as e:
                print(f"❌ {csv_filename} 로드 실패: {e}")
                continue
        except Exception as e:
            print(f"❌ {csv_filename} 로드 실패: {e}")
            continue

        if df.empty:
            print(f"⚠️ 경고: {csv_filename} 파일이 비어있습니다.")
            continue

        final_df = process_srum_csv(df, table_type)
        final_df.to_csv(output_filepath, index=False, encoding='utf-8-sig')
        print(f"✅ 처리 완료: {output_filepath} ({len(final_df):,}개 행)")

def run_all_srum_processing():
    """모든 SRUM CSV 파일 처리"""
    processing_tasks = list(CSV_FILENAMES.keys())
    
    for artifact_key in processing_tasks:
        main_processing_logic(artifact_key)

if __name__ == "__main__":
    print("--- SRUM 태깅 시작 (총 7종) ---")
    run_all_srum_processing()
    print("\n--- 모든 처리 완료 ---")