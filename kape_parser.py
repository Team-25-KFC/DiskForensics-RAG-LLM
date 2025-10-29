import subprocess
import os
import json
import datetime
from pathlib import Path

# ==================== 설정 ====================
KAPE_EXE = r"D:\df_tool\kape\KAPE\kape.exe"
MOUNTED_DRIVE = "G:"  # 마운트된 드라이브
OUTPUT_BASE = r"D:\luu\kape_output"  # 출력 기본 경로

# 18가지 아티팩트 매핑 (Target, Module)
ARTIFACT_CONFIGS = {
    "registry_system": {
        "name": "Registry System Hives",
        "target": "RegistryHivesSystem",
        "modules": ["RECmd_BasicSystemInfo", "RECmd_SystemASEPs"],
        "description": "SYSTEM, SOFTWARE, SAM, SECURITY"
    },
    "registry_user": {
        "name": "Registry User Hives",
        "target": "RegistryHivesUser",
        "modules": ["RECmd_UserActivity"],
        "description": "NTUSER.DAT"
    },
    "event_logs": {
        "name": "Windows Event Logs",
        "target": "EventLogs",
        "modules": ["EvtxECmd"],
        "description": "Windows Event Logs"
    },
    "mft": {
        "name": "$MFT",
        "target": "$MFT",
        "modules": ["MFTECmd"],
        "description": "Master File Table"
    },
    "logfile": {
        "name": "$LogFile",
        "target": "$LogFile",
        "modules": ["NTFSLogTracker_$LogFile"],
        "description": "NTFS $LogFile"
    },
    "recycle_bin": {
        "name": "Recycle Bin",
        "target": "RecycleBin",
        "modules": ["RBCmd"],
        "description": "$Recycle.Bin"
    },
    "prefetch": {
        "name": "Prefetch",
        "target": "Prefetch",
        "modules": ["PECmd"],
        "description": "Windows Prefetch"
    },
    "startup": {
        "name": "Startup Folders",
        "target": "StartupFolders",
        "modules": ["LECmd"],
        "description": "Startup Programs"
    },
    "browser": {
        "name": "Web Browsers",
        "target": "WebBrowsers",
        "modules": ["NirSoft_BrowsingHistoryView"],
        "description": "Browser History (IE, Chrome, Firefox, Edge)"
    }
}
# =============================================


class KAPEParser:
    def __init__(self, kape_exe, mounted_drive, output_base):
        """
        KAPE 파서 초기화
        
        Args:
            kape_exe: KAPE 실행 파일 경로
            mounted_drive: 마운트된 드라이브 (예: "G:")
            output_base: 출력 기본 디렉토리
        """
        self.kape_exe = kape_exe
        self.mounted_drive = mounted_drive.rstrip("\\")
        self.output_base = output_base
        
        # 출력 디렉토리 생성
        os.makedirs(output_base, exist_ok=True)
    
    def run_kape(self, artifact_key, target, modules):
        """
        KAPE 실행 (Target + Module)
        
        Args:
            artifact_key: 아티팩트 키 (예: "registry_system")
            target: KAPE Target 이름
            modules: KAPE Module 리스트
            
        Returns:
            dict: 실행 결과
        """
        # 타임스탬프
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 출력 디렉토리
        tdest = os.path.join(self.output_base, f"{artifact_key}_target_{timestamp}")
        mdest = os.path.join(self.output_base, f"{artifact_key}_module_{timestamp}")
        
        print(f"\n{'=' * 60}")
        print(f"아티팩트: {ARTIFACT_CONFIGS[artifact_key]['name']}")
        print(f"Target: {target}")
        print(f"Modules: {', '.join(modules)}")
        print(f"{'=' * 60}")
        
        # Step 1: Target 수집
        print(f"\n[1/2] Target 수집 중...")
        target_result = self._run_target(target, tdest)
        
        if not target_result['success']:
            return {
                'artifact': artifact_key,
                'success': False,
                'message': f"Target 수집 실패: {target_result['message']}",
                'tdest': tdest,
                'mdest': None
            }
        
        print(f"✓ Target 수집 완료: {tdest}")
        
        # Step 2: Module 실행
        print(f"\n[2/2] Module 실행 중...")
        module_result = self._run_modules(tdest, modules, mdest)
        
        if not module_result['success']:
            return {
                'artifact': artifact_key,
                'success': False,
                'message': f"Module 실행 실패: {module_result['message']}",
                'tdest': tdest,
                'mdest': mdest
            }
        
        print(f"✓ Module 실행 완료: {mdest}")
        
        return {
            'artifact': artifact_key,
            'success': True,
            'message': '성공',
            'tdest': tdest,
            'mdest': mdest,
            'timestamp': timestamp
        }
    
    def _run_target(self, target, tdest):
        """
        KAPE Target 실행
        
        Args:
            target: Target 이름
            tdest: 출력 디렉토리
            
        Returns:
            dict: 실행 결과
        """
        cmd = [
            self.kape_exe,
            "--tsource", self.mounted_drive,
            "--target", target,
            "--tdest", tdest,
            "--vss"  # Volume Shadow Copy도 처리
        ]
        
        print(f"실행: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                cwd=os.path.dirname(self.kape_exe)
            )
            
            # 출력 확인
            if result.returncode == 0 or os.path.exists(tdest):
                return {
                    'success': True,
                    'message': '수집 완료',
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'message': result.stderr or result.stdout,
                    'output': result.stdout
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': str(e),
                'output': None
            }
    
    def _run_modules(self, msource, modules, mdest):
        """
        KAPE Module 실행
        
        Args:
            msource: Module 소스 디렉토리 (Target 출력)
            modules: Module 리스트
            mdest: Module 출력 디렉토리
            
        Returns:
            dict: 실행 결과
        """
        # 여러 Module을 쉼표로 구분
        module_str = "!EZParser"  # EZParser: Eric Zimmerman Tools 통합 실행
        
        cmd = [
            self.kape_exe,
            "--msource", msource,
            "--module", module_str,
            "--mdest", mdest,
            "--mef", "csv"  # CSV 출력
        ]
        
        print(f"실행: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                cwd=os.path.dirname(self.kape_exe)
            )
            
            # 출력 확인
            if result.returncode == 0 or os.path.exists(mdest):
                return {
                    'success': True,
                    'message': '파싱 완료',
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'message': result.stderr or result.stdout,
                    'output': result.stdout
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': str(e),
                'output': None
            }
    
    def parse_artifact(self, artifact_key):
        """
        특정 아티팩트 파싱
        
        Args:
            artifact_key: 아티팩트 키
            
        Returns:
            dict: 파싱 결과
        """
        if artifact_key not in ARTIFACT_CONFIGS:
            return {
                'success': False,
                'message': f'알 수 없는 아티팩트: {artifact_key}'
            }
        
        config = ARTIFACT_CONFIGS[artifact_key]
        
        return self.run_kape(
            artifact_key=artifact_key,
            target=config['target'],
            modules=config['modules']
        )
    
    def parse_all(self, artifact_keys=None):
        """
        여러 아티팩트 일괄 파싱
        
        Args:
            artifact_keys: 파싱할 아티팩트 키 리스트 (None이면 전체)
            
        Returns:
            list: 파싱 결과 리스트
        """
        if artifact_keys is None:
            artifact_keys = ARTIFACT_CONFIGS.keys()
        
        results = []
        
        print("=" * 60)
        print(f"KAPE 아티팩트 파싱 시작")
        print(f"마운트된 드라이브: {self.mounted_drive}")
        print(f"출력 경로: {self.output_base}")
        print(f"파싱할 아티팩트: {len(artifact_keys)}개")
        print("=" * 60)
        
        for i, artifact_key in enumerate(artifact_keys, 1):
            print(f"\n\n[{i}/{len(artifact_keys)}] {artifact_key}")
            
            result = self.parse_artifact(artifact_key)
            results.append(result)
            
            if result['success']:
                print(f"✓ 성공: {artifact_key}")
            else:
                print(f"✗ 실패: {artifact_key} - {result['message']}")
        
        # 요약
        print("\n" + "=" * 60)
        print("파싱 완료 요약")
        print("=" * 60)
        
        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count
        
        print(f"성공: {success_count}개")
        print(f"실패: {fail_count}개")
        
        # 결과 저장
        result_file = os.path.join(self.output_base, "parsing_results.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n결과 저장: {result_file}")
        
        return results


def main():
    """
    KAPE 파서 실행
    """
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    
    # 사용 예제 1: 특정 아티팩트만 파싱
    # result = parser.parse_artifact("registry_system")
    
    # 사용 예제 2: 여러 아티팩트 선택 파싱
    # results = parser.parse_all(["registry_system", "event_logs", "prefetch"])
    
    # 사용 예제 3: 18가지 전체 파싱
    results = parser.parse_all()


if __name__ == "__main__":
    main()
