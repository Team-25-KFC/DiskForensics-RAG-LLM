import csv
import json
import re
from pathlib import Path
from datetime import datetime, timedelta

class ArtifactTagger:
    def __init__(self):
        # 파일 확장자별 포맷 매핑
        self.format_map = {
            'FORMAT_DOCUMENT': ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.hwp', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods'],
            'FORMAT_IMAGE': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tif', '.tiff', '.raw'],
            'FORMAT_VIDEO': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.mpg', '.mpeg', '.3gp'],
            'FORMAT_AUDIO': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus'],
            'FORMAT_ARCHIVE': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.cab', '.arj'],
            'FORMAT_EXECUTABLE': ['.exe', '.dll', '.sys', '.bat', '.cmd', '.msi', '.com', '.scr'],
            'FORMAT_SCRIPT': ['.ps1', '.vbs', '.js', '.py', '.sh', '.php', '.rb', '.pl', '.psm1'],
            'FORMAT_DATABASE': ['.db', '.sqlite', '.mdb', '.accdb', '.dbf', '.sdf'],
            'FORMAT_LOG': ['.log', '.evtx', '.evt', '.etl'],
            'FORMAT_CONFIG': ['.ini', '.conf', '.cfg', '.xml', '.json', '.yaml', '.yml', '.toml']
        }
        
        # 경로별 시스템 영역 매핑
        self.area_patterns = {
            'AREA_SYSTEM32': r'(?i)\\system32\\|\\syswow64\\',
            'AREA_USER_DESKTOP': r'(?i)\\desktop\\',
            'AREA_USER_DOCUMENTS': r'(?i)\\documents\\|\\my documents\\',
            'AREA_USER_DOWNLOADS': r'(?i)\\downloads\\',
            'AREA_APPDATA_LOCAL': r'(?i)\\appdata\\local\\',
            'AREA_APPDATA_ROAMING': r'(?i)\\appdata\\roaming\\',
            'AREA_PROGRAMFILES': r'(?i)\\program files\\|\\program files \(x86\)\\',
            'AREA_PROGRAMDATA': r'(?i)\\programdata\\',
            'AREA_TEMP': r'(?i)\\temp\\|\\tmp\\|\\temporary\\',
            'AREA_NETWORK_RELATED': r'(?i)\\network\\|\\share\\|\\smb\\|\\netlogon\\',
            'AREA_SECURITY_RELATED': r'(?i)\\security\\|\\firewall\\|\\defender\\|\\windowsdefender\\'
        }
        
        # 보안 관련 패턴
        self.security_patterns = {
            'SEC_SUSPICIOUS_NAME': r'(?i)(crack|keygen|patch|hack|payload|malware|trojan|virus|ransomware|backdoor|rootkit|mimikatz|pwdump)',
            'SEC_SUSPICIOUS_PATH': r'(?i)\\temp\\.*\.exe|\\downloads\\.*\.exe|\\appdata\\local\\temp\\.*\.exe',
            'SEC_PERSISTENCE_PATH': r'(?i)\\startup\\|\\run\\|\\runonce\\|\\userinit|\\winlogon',
            'SEC_STARTUP': r'(?i)\\startup\\|\\start menu\\.*\\startup',
            'SEC_TASK_SCHEDULED': r'(?i)\\tasks\\|\\schedlgu\.txt|\\at\.exe',
            'SEC_FIREWALL_RELATED': r'(?i)firewall|\\wf\.msc|\\netsh|\\advfirewall'
        }
        
        # 사용자 활동 패턴
        self.activity_patterns = {
            'ACT_DOWNLOAD': r'(?i)\\downloads\\|\.crdownload$|\.download$|\.part$',
            'ACT_UPLOAD': r'(?i)\\uploads\\|\\outbox\\|\\sent\\',
            'ACT_INSTALL': r'(?i)\\installer|setup\.exe|install\.exe|\\msi\\|unattend\.xml',
            'ACT_UNINSTALL': r'(?i)uninstall|\\unins|\\remove|uninst\.exe',
            'ACT_EXECUTE': r'(?i)\.exe$|\.bat$|\.cmd$|\.com$|\.scr$',
            'ACT_COMMUNICATION': r'(?i)\\mail|\\outlook|\\thunderbird|\\skype|\\teams|\\slack|\\discord|\\zoom|\\telegram'
        }
        
        # 아티팩트 타입 패턴
        self.artifact_patterns = {
            'ARTIFACT_REGISTRY': r'(?i)\.reg$|\\registry\\|ntuser\.dat|sam$|system$|software$|security$',
            'ARTIFACT_EVENT_LOG': r'(?i)\.evtx$|\.evt$|\\winevt\\|\\eventlog\\',
            'ARTIFACT_PREFETCH': r'(?i)\\prefetch\\.*\.pf$',
            'ARTIFACT_LNK': r'(?i)\.lnk$',
            'ARTIFACT_BROWSER_HISTORY': r'(?i)\\history|\\places\.sqlite|\\webdata|\\visited',
            'ARTIFACT_COOKIE': r'(?i)\\cookies|\.cookie',
            'ARTIFACT_CACHE': r'(?i)\\cache\\|\\webcache\\',
            'ARTIFACT_EMAIL': r'(?i)\.pst$|\.ost$|\.eml$|\.msg$|\.mbox$',
            'ARTIFACT_DB': r'(?i)\.db$|\.sqlite$|\.sqlite3$'
        }
        
        # 파일 작업 키워드 (이벤트 설명이나 메모 필드용)
        self.file_operation_keywords = {
            'FILE_CREATE': r'(?i)creat|new file|file creat|created',
            'FILE_MODIFY': r'(?i)modif|change|edit|update|alter|written',
            'FILE_DELETE': r'(?i)delet|remov|erase',
            'FILE_RENAME': r'(?i)renam|name chang',
            'FILE_MOVE': r'(?i)move|relocat|transfer',
            'FILE_COPY': r'(?i)cop|duplicat',
            'FILE_ACCESS': r'(?i)access|open|read|view'
        }

    def tag_file_format(self, filename):
        """파일 포맷 태그 추출"""
        tags = []
        ext = Path(filename).suffix.lower()
        
        for format_tag, extensions in self.format_map.items():
            if ext in extensions:
                tags.append(format_tag)
        
        return tags

    def tag_system_area(self, filepath):
        """시스템 영역 태그 추출"""
        tags = []
        
        for area_tag, pattern in self.area_patterns.items():
            if re.search(pattern, filepath):
                tags.append(area_tag)
        
        return tags

    def tag_security(self, filepath, filename):
        """보안 관련 태그 추출"""
        tags = []
        full_path = filepath + filename
        
        # 실행 파일 체크
        if filename.lower().endswith(('.exe', '.dll', '.sys', '.com', '.scr')):
            tags.append('SEC_EXECUTABLE')
        
        # 숨김 실행 파일
        if filename.lower().endswith(('.exe', '.dll', '.sys')) and (
            'hidden' in full_path.lower() or 
            re.search(r'(?i)^\.|\\\.', filename)
        ):
            tags.append('SEC_HIDDEN_EXECUTABLE')
        
        # 패턴 기반 보안 태그
        for sec_tag, pattern in self.security_patterns.items():
            if re.search(pattern, full_path):
                tags.append(sec_tag)
        
        return tags

    def tag_user_activity(self, filepath, filename):
        """사용자 활동 태그 추출"""
        tags = []
        full_path = filepath + filename
        
        for act_tag, pattern in self.activity_patterns.items():
            if re.search(pattern, full_path):
                tags.append(act_tag)
        
        return tags

    def tag_artifact_type(self, filepath, filename):
        """아티팩트 타입 태그 추출"""
        tags = ['ARTIFACT_FILE']  # 기본 태그
        full_path = filepath + filename
        
        for artifact_tag, pattern in self.artifact_patterns.items():
            if re.search(pattern, full_path):
                tags.append(artifact_tag)
        
        return tags

    def tag_timeline(self, created_time, modified_time, accessed_time):
        """시간 기반 태그 추출"""
        tags = []
        now = datetime.now()
        
        # 날짜 파싱 시도 (다양한 형식 지원)
        times = []
        for time_str in [created_time, modified_time, accessed_time]:
            if not time_str or str(time_str).strip().upper() in ['N/A', 'NULL', '', 'NONE']:
                continue
            try:
                # ISO 형식
                parsed_time = datetime.fromisoformat(str(time_str).replace('Z', '+00:00').split('+')[0].split('.')[0])
                times.append(parsed_time)
            except:
                try:
                    # 일반적인 형식들 시도
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S']:
                        try:
                            parsed_time = datetime.strptime(str(time_str).split('.')[0], fmt)
                            times.append(parsed_time)
                            break
                        except:
                            continue
                except:
                    pass
        
        if times:
            # 가장 최근 시간 기준
            latest_time = max(times)
            time_diff = now - latest_time
            
            if time_diff <= timedelta(days=7):
                tags.append('TIME_RECENT')
            elif time_diff <= timedelta(days=30):
                tags.append('TIME_WEEK')
            elif time_diff <= timedelta(days=90):
                tags.append('TIME_MONTH')
            else:
                tags.append('TIME_OLD')
        
        # MAC 타임 태그
        if created_time and str(created_time).strip().upper() not in ['N/A', 'NULL', '', 'NONE']:
            tags.append('TIME_CREATED_TIME')
        if modified_time and str(modified_time).strip().upper() not in ['N/A', 'NULL', '', 'NONE']:
            tags.append('TIME_MODIFIED_TIME')
        if accessed_time and str(accessed_time).strip().upper() not in ['N/A', 'NULL', '', 'NONE']:
            tags.append('TIME_ACCESSED_TIME')
        
        return tags

    def tag_file_operation(self, row):
        """파일 작업 및 상태 태그 추출"""
        tags = []
        
        # 모든 필드를 합쳐서 검색할 텍스트
        search_text = ' '.join([str(v).lower() for v in row.values() if v])
        
        # 파일 작업 태그 (이벤트 설명, 메모, 코멘트 등에서)
        for operation_tag, pattern in self.file_operation_keywords.items():
            if re.search(pattern, search_text):
                tags.append(operation_tag)
        
        # 파일 속성 태그
        attributes = row.get('attributes', row.get('attribute', row.get('attr', ''))).lower()
        if 'hidden' in attributes or 'h' in attributes.split():
            tags.append('FILE_HIDDEN')
        if 'system' in attributes or 's' in attributes.split():
            tags.append('FILE_SYSTEM')
        if 'temp' in attributes or 'temporary' in search_text:
            tags.append('FILE_TEMP')
        if 'encrypted' in attributes or 'encrypt' in search_text:
            tags.append('FILE_ENCRYPTED')
        if 'compressed' in attributes or 'compress' in search_text:
            tags.append('FILE_COMPRESSED')
        
        # 파일 상태 태그
        deleted_field = str(row.get('deleted', row.get('is_deleted', row.get('status', '')))).lower()
        allocated_field = str(row.get('allocated', row.get('is_allocated', ''))).lower()
        slack_field = str(row.get('slack', row.get('file_slack', ''))).lower()
        recovered_field = str(row.get('recovered', row.get('is_recovered', ''))).lower()
        
        # 삭제 여부
        if deleted_field in ['true', '1', 'yes', 'deleted'] or 'delete' in search_text:
            tags.append('FILE_DELETED')
        else:
            tags.append('FILE_ACTIVE')
        
        # 복구됨
        if recovered_field in ['true', '1', 'yes', 'recovered'] or 'recover' in search_text:
            tags.append('FILE_RECOVERED')
        
        # 할당되지 않음
        if allocated_field in ['false', '0', 'no', 'unallocated'] or 'unallocated' in search_text:
            tags.append('FILE_UNALLOCATED')
        
        # 슬랙 영역
        if slack_field in ['true', '1', 'yes'] or 'slack' in search_text:
            tags.append('FILE_SLACK')
        
        return tags

    def process_csv(self, input_csv, output_jsonl):
        """CSV 파일을 읽어 태그를 붙이고 JSONL로 저장"""
        results = []
        
        with open(input_csv, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # 필드 추출 (다양한 컬럼명 지원)
                filename = row.get('filename', row.get('name', row.get('file_name', row.get('file', ''))))
                filepath = row.get('filepath', row.get('path', row.get('file_path', row.get('full_path', ''))))
                created = row.get('created', row.get('created_time', row.get('creation_time', row.get('ctime', ''))))
                modified = row.get('modified', row.get('modified_time', row.get('modification_time', row.get('mtime', ''))))
                accessed = row.get('accessed', row.get('accessed_time', row.get('access_time', row.get('atime', ''))))
                
                # 경로와 파일명 결합
                if not filepath and filename:
                    filepath = ''
                elif filepath and not filepath.endswith('\\') and not filepath.endswith('/'):
                    if '\\' in filepath or '/' in filepath:
                        pass  # 이미 전체 경로
                    else:
                        filepath = filepath + '\\'
                
                # 모든 태그 수집
                tags = []
                tags.extend(self.tag_file_format(filename))
                tags.extend(self.tag_system_area(filepath))
                tags.extend(self.tag_security(filepath, filename))
                tags.extend(self.tag_user_activity(filepath, filename))
                tags.extend(self.tag_artifact_type(filepath, filename))
                tags.extend(self.tag_timeline(created, modified, accessed))
                tags.extend(self.tag_file_operation(row))
                
                # 중복 제거
                tags = list(set(tags))
                
                # 결과 객체 생성
                result = {
                    'original_data': row,
                    'tags': sorted(tags),  # 정렬하여 보기 쉽게
                    'tag_count': len(tags),
                    'categories': self.categorize_tags(tags)
                }
                
                results.append(result)
        
        # JSONL 형식으로 저장
        with open(output_jsonl, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(json.dumps(result, ensure_ascii=False) + '\n')
        
        print(f"✅ 처리 완료: {len(results)}개 항목")
        print(f"📁 출력 파일: {output_jsonl}")
        
        # 통계 출력
        self.print_statistics(results)
        
        return results

    def categorize_tags(self, tags):
        """태그를 카테고리별로 분류"""
        categories = {
            'file_system': [],
            'file_format': [],
            'system_area': [],
            'artifact_type': [],
            'security': [],
            'timeline': [],
            'user_activity': []
        }
        
        for tag in tags:
            if tag.startswith('FILE_'):
                categories['file_system'].append(tag)
            elif tag.startswith('FORMAT_'):
                categories['file_format'].append(tag)
            elif tag.startswith('AREA_'):
                categories['system_area'].append(tag)
            elif tag.startswith('ARTIFACT_'):
                categories['artifact_type'].append(tag)
            elif tag.startswith('SEC_'):
                categories['security'].append(tag)
            elif tag.startswith('TIME_'):
                categories['timeline'].append(tag)
            elif tag.startswith('ACT_'):
                categories['user_activity'].append(tag)
        
        # 빈 카테고리 제거
        return {k: v for k, v in categories.items() if v}

    def print_statistics(self, results):
        """태그 통계 출력"""
        tag_counts = {}
        category_counts = {
            'FILE_*': 0,
            'FORMAT_*': 0,
            'AREA_*': 0,
            'ARTIFACT_*': 0,
            'SEC_*': 0,
            'TIME_*': 0,
            'ACT_*': 0
        }
        
        for result in results:
            for tag in result['tags']:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
                
                # 카테고리별 카운트
                prefix = tag.split('_')[0] + '_*'
                if prefix in category_counts:
                    category_counts[prefix] += 1
        
        print("\n" + "="*60)
        print("📊 카테고리별 태그 통계")
        print("="*60)
        for category, count in sorted(category_counts.items()):
            print(f"  {category:15} : {count:5} 개")
        
        print("\n" + "="*60)
        print("📊 상위 20개 태그")
        print("="*60)
        for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"  {tag:30} : {count:5} 개")


# 사용 예시
if __name__ == "__main__":
    import glob
    import os
    
    tagger = ArtifactTagger()
    
    # 현재 디렉토리의 모든 CSV 파일 찾기
    csv_files = glob.glob("*.csv")
    
    if not csv_files:
        print("❌ 현재 디렉토리에 CSV 파일이 없습니다.")
    else:
        print(f"📂 발견된 CSV 파일: {len(csv_files)}개\n")
        
        total_processed = 0
        success_count = 0
        
        for csv_file in csv_files:
            print(f"\n{'='*60}")
            print(f"🔄 처리 중: {csv_file}")
            print(f"{'='*60}")
            
            # 출력 파일명 생성 (원본명_tagged.jsonl)
            base_name = os.path.splitext(csv_file)[0]
            output_file = f"{base_name}_tagged.jsonl"
            
            try:
                results = tagger.process_csv(csv_file, output_file)
                total_processed += len(results)
                success_count += 1
                print(f"✅ 완료: {csv_file} → {output_file}")
            except Exception as e:
                print(f"❌ 오류 발생 ({csv_file}): {e}")
                import traceback
                traceback.print_exc()
        
        print(f"\n{'='*60}")
        print(f"📊 전체 처리 결과")
        print(f"{'='*60}")
        print(f"✅ 성공: {success_count}/{len(csv_files)} 파일")
        print(f"📝 총 처리 항목: {total_processed}개")
        print(f"{'='*60}")
