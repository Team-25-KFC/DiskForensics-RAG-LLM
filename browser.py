import os
import json
import datetime
from pathlib import Path

# ==================== 설정 ====================
# 마운트된 드라이브 경로 (예: E:, F: 등)
MOUNTED_DRIVE = "G:"  # 마운트된 드라이브 문자로 변경

# 브라우저 관련 경로들
BROWSER_PATHS = {
    'ie_program': r"Program Files\Internet Explorer",
    'ie_program_x86': r"Program Files (x86)\Internet Explorer",
    'ie_cache': r"Users\*\AppData\Local\Microsoft\Windows\INetCache",
    'ie_cookies': r"Users\*\AppData\Local\Microsoft\Windows\INetCookies",
    'ie_history': r"Users\*\AppData\Local\Microsoft\Windows\WebCache",
    'chrome_data': r"Users\*\AppData\Local\Google\Chrome\User Data",
    'firefox_data': r"Users\*\AppData\Roaming\Mozilla\Firefox\Profiles",
    'edge_data': r"Users\*\AppData\Local\Microsoft\Edge\User Data",
}

# 출력 파일
OUTPUT_FILE = "browser_artifacts.jsonl"
# =============================================


class BrowserParser:
    def __init__(self, drive_letter):
        """
        브라우저 아티팩트 파서 초기화
        
        Args:
            drive_letter: 마운트된 드라이브 문자 (예: "E:")
        """
        self.drive = drive_letter.rstrip("\\")
        self.artifacts = []
        
    def get_file_metadata(self, file_path):
        """
        파일의 메타데이터 추출
        
        Args:
            file_path: 파일 경로
            
        Returns:
            dict: 파일 메타데이터
        """
        try:
            stat_info = os.stat(file_path)
            
            # 파일 시간 정보
            created = datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            modified = datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            accessed = datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat()
            
            return {
                'created': created,
                'modified': modified,
                'accessed': accessed,
                'size': stat_info.st_size,
            }
        except Exception as e:
            return {
                'created': None,
                'modified': None,
                'accessed': None,
                'size': None,
                'error': str(e)
            }
    
    def get_directory_info(self, dir_path):
        """
        디렉토리 정보 추출
        
        Args:
            dir_path: 디렉토리 경로
            
        Returns:
            dict: 디렉토리 정보
        """
        try:
            file_count = 0
            total_size = 0
            
            for root, dirs, files in os.walk(dir_path):
                file_count += len(files)
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        total_size += os.path.getsize(file_path)
                    except:
                        pass
            
            return {
                'file_count': file_count,
                'total_size': total_size,
            }
        except Exception as e:
            return {
                'file_count': 0,
                'total_size': 0,
                'error': str(e)
            }
    
    def scan_ie_program_folder(self, folder_path, path_key):
        """
        Internet Explorer 프로그램 폴더 스캔
        
        Args:
            folder_path: 스캔할 폴더 경로
            path_key: 경로 키 (ie_program, ie_program_x86)
            
        Returns:
            list: 발견된 아티팩트 목록
        """
        artifacts = []
        full_path = os.path.join(self.drive, folder_path)
        
        if not os.path.exists(full_path):
            print(f"⚠ 경로 없음: {full_path}")
            return artifacts
        
        print(f"✓ 스캔 중: {full_path}")
        
        try:
            # IE 실행 파일 및 DLL 파일 찾기
            for item in os.listdir(full_path):
                item_path = os.path.join(full_path, item)
                
                if os.path.isfile(item_path):
                    ext = os.path.splitext(item)[1].lower()
                    
                    # 실행 파일, DLL, 설정 파일만
                    if ext in ['.exe', '.dll', '.inf', '.xml']:
                        metadata = self.get_file_metadata(item_path)
                        
                        artifact = {
                            'artifact_type': 'ie_program',
                            'location': path_key,
                            'file_name': item,
                            'file_path': item_path,
                            'file_extension': ext,
                            'created_time': metadata.get('created'),
                            'modified_time': metadata.get('modified'),
                            'accessed_time': metadata.get('accessed'),
                            'file_size': metadata.get('size'),
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        
                        artifacts.append(artifact)
                        print(f"  → 발견: {item}")
        
        except PermissionError:
            print(f"✗ 권한 없음: {full_path}")
        except Exception as e:
            print(f"✗ 오류 [{full_path}]: {e}")
        
        return artifacts
    
    def scan_user_browser_data(self, folder_pattern, artifact_type):
        """
        사용자별 브라우저 데이터 스캔
        
        Args:
            folder_pattern: 스캔할 폴더 패턴 (예: "Users\\*\\AppData\\...")
            artifact_type: 아티팩트 타입
            
        Returns:
            list: 발견된 아티팩트 목록
        """
        artifacts = []
        
        # Users\*\... 형태 처리
        if '*' not in folder_pattern:
            return artifacts
        
        base_path = folder_pattern.split('*')[0]
        pattern = folder_pattern.split('*')[1]
        
        users_path = os.path.join(self.drive, base_path.strip('\\'))
        
        if not os.path.exists(users_path):
            print(f"⚠ 경로 없음: {users_path}")
            return artifacts
        
        try:
            for user_dir in os.listdir(users_path):
                user_data_path = os.path.join(users_path, user_dir, pattern.strip('\\'))
                
                if os.path.exists(user_data_path):
                    print(f"✓ 스캔 중: {user_data_path}")
                    
                    # 디렉토리 정보 수집
                    dir_info = self.get_directory_info(user_data_path)
                    
                    artifact = {
                        'artifact_type': artifact_type,
                        'user': user_dir,
                        'directory_path': user_data_path,
                        'file_count': dir_info.get('file_count'),
                        'total_size': dir_info.get('total_size'),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    # 주요 파일 목록 (상위 10개)
                    important_files = self._get_important_files(user_data_path)
                    if important_files:
                        artifact['important_files'] = important_files
                    
                    artifacts.append(artifact)
                    print(f"  → 사용자: {user_dir}, 파일 수: {dir_info.get('file_count')}")
        
        except PermissionError:
            print(f"✗ 권한 없음: {users_path}")
        except Exception as e:
            print(f"✗ 오류 [{users_path}]: {e}")
        
        return artifacts
    
    def _get_important_files(self, directory, max_files=10):
        """
        디렉토리에서 중요한 파일 목록 추출
        
        Args:
            directory: 스캔할 디렉토리
            max_files: 최대 파일 수
            
        Returns:
            list: 중요 파일 목록
        """
        important_files = []
        
        # 중요한 파일 확장자 및 이름
        important_extensions = ['.db', '.sqlite', '.json', '.log', '.dat']
        important_names = ['History', 'Cookies', 'Cache', 'WebCacheV', 'places.sqlite']
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    # 중요 파일인지 확인
                    ext = os.path.splitext(file)[1].lower()
                    is_important = ext in important_extensions or any(name in file for name in important_names)
                    
                    if is_important:
                        file_path = os.path.join(root, file)
                        metadata = self.get_file_metadata(file_path)
                        
                        important_files.append({
                            'file_name': file,
                            'file_path': file_path,
                            'file_size': metadata.get('size'),
                            'modified_time': metadata.get('modified')
                        })
                        
                        if len(important_files) >= max_files:
                            return important_files
        
        except Exception as e:
            pass
        
        return important_files
    
    def parse_all(self):
        """
        모든 브라우저 아티팩트 파싱
        
        Returns:
            list: 모든 아티팩트 목록
        """
        print("=" * 60)
        print("브라우저 아티팩트 파싱 시작")
        print("=" * 60)
        print(f"마운트된 드라이브: {self.drive}\n")
        
        all_artifacts = []
        
        # 1. Internet Explorer 프로그램 폴더
        print("\n[1] Internet Explorer 프로그램 폴더")
        print("-" * 60)
        for key in ['ie_program', 'ie_program_x86']:
            if key in BROWSER_PATHS:
                artifacts = self.scan_ie_program_folder(BROWSER_PATHS[key], key)
                all_artifacts.extend(artifacts)
        
        # 2. IE 캐시, 쿠키, 히스토리
        print("\n[2] Internet Explorer 사용자 데이터")
        print("-" * 60)
        for key in ['ie_cache', 'ie_cookies', 'ie_history']:
            if key in BROWSER_PATHS:
                artifacts = self.scan_user_browser_data(BROWSER_PATHS[key], key)
                all_artifacts.extend(artifacts)
        
        # 3. 기타 브라우저 (Chrome, Firefox, Edge)
        print("\n[3] 기타 브라우저 데이터")
        print("-" * 60)
        for key in ['chrome_data', 'firefox_data', 'edge_data']:
            if key in BROWSER_PATHS:
                artifacts = self.scan_user_browser_data(BROWSER_PATHS[key], key)
                all_artifacts.extend(artifacts)
        
        print("\n" + "=" * 60)
        print(f"총 {len(all_artifacts)}개의 아티팩트 발견")
        print("=" * 60)
        
        return all_artifacts
    
    def save_to_jsonl(self, artifacts, output_file):
        """
        아티팩트를 JSONL 형식으로 저장
        
        Args:
            artifacts: 아티팩트 목록
            output_file: 출력 파일 경로
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for artifact in artifacts:
                    json_line = json.dumps(artifact, ensure_ascii=False)
                    f.write(json_line + '\n')
            
            print(f"\n✓ 저장 완료: {output_file}")
            print(f"✓ 총 {len(artifacts)}개 레코드 저장")
            
        except Exception as e:
            print(f"\n✗ 저장 실패: {e}")


def main():
    """
    브라우저 아티팩트 파싱 메인 함수
    """
    # 파서 초기화
    parser = BrowserParser(MOUNTED_DRIVE)
    
    # 모든 브라우저 아티팩트 파싱
    artifacts = parser.parse_all()
    
    # JSONL 파일로 저장
    if artifacts:
        parser.save_to_jsonl(artifacts, OUTPUT_FILE)
        
        # 샘플 출력
        print("\n" + "=" * 60)
        print("샘플 레코드 (첫 3개)")
        print("=" * 60)
        for i, artifact in enumerate(artifacts[:3], 1):
            print(f"\n[{i}]")
            print(json.dumps(artifact, indent=2, ensure_ascii=False))
    else:
        print("\n⚠ 발견된 아티팩트가 없습니다.")


if __name__ == "__main__":
    main()
