import subprocess
import time
import os
import sys
import re

# ==================== 설정 ====================
AIM_CLI_PATH = r"D:\df_tool\Arsenal-Image-Mounter-v3.11.307\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
E01_FILE_PATH = r"D:\luu\win10.E01"
# =============================================

class AIMManager:
    def __init__(self, aim_cli_path="aim_cli.exe"):
        """
        AIM CLI 관리자 초기화
        
        Args:
            aim_cli_path: aim_cli.exe의 경로 (기본값: "aim_cli.exe")
        """
        self.aim_cli_path = aim_cli_path
        
    def mount_image(self, filename, readonly=True, provider="LibEwf", online=True):
        """
        E01 이미지 파일을 가상 마운트
        
        Args:
            filename: 마운트할 E01 파일 경로
            readonly: 읽기 전용 모드 (기본값: True)
            provider: 제공자 (기본값: "LibEwf")
            online: 온라인 모드 (기본값: True)
            
        Returns:
            dict: 마운트 결과 {'success': bool, 'device_number': int, 'message': str}
        """
        # 파일 존재 확인
        if not os.path.exists(filename):
            return {
                'success': False,
                'device_number': None,
                'message': f'파일을 찾을 수 없습니다: {filename}'
            }
        
        # 명령어 구성
        cmd = [
            self.aim_cli_path,
            '--mount',
            f'--filename={filename}',
            f'--provider={provider}'
        ]
        
        if readonly:
            cmd.append('--readonly')
        
        if online:
            cmd.append('--online')
        
        print(f"실행 명령어: {' '.join(cmd)}")
        
        try:
            # AIM CLI 실행
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            print(f"반환 코드: {result.returncode}")
            print(f"출력:\n{result.stdout}")
            
            if result.stderr:
                print(f"오류:\n{result.stderr}")
            
            # 디바이스 번호 추출 (출력에서 파싱)
            device_number = self._extract_device_number(result.stdout)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'device_number': device_number,
                    'message': '마운트 성공',
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'device_number': None,
                    'message': f'마운트 실패: {result.stderr}',
                    'output': result.stdout
                }
                
        except FileNotFoundError:
            return {
                'success': False,
                'device_number': None,
                'message': f'AIM CLI를 찾을 수 없습니다: {self.aim_cli_path}'
            }
        except Exception as e:
            return {
                'success': False,
                'device_number': None,
                'message': f'오류 발생: {str(e)}'
            }
    
    def _extract_device_number(self, output):
        """
        AIM CLI 출력에서 디바이스 번호 추출
        
        Args:
            output: AIM CLI 출력 텍스트
            
        Returns:
            int: 디바이스 번호 또는 None
        """
        # 일반적인 패턴: "Device number: 0" 또는 "\\.\PhysicalDrive0"
        patterns = [
            r'Device number[:\s]+(\d+)',
            r'PhysicalDrive(\d+)',
            r'device\s+(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
    
    def list_devices(self):
        """
        현재 마운트된 장치 목록 조회
        
        Returns:
            dict: 결과 {'success': bool, 'devices': list, 'message': str}
        """
        cmd = [self.aim_cli_path, '--list']
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'devices': result.stdout,
                    'message': '조회 성공'
                }
            else:
                return {
                    'success': False,
                    'devices': None,
                    'message': f'조회 실패: {result.stderr}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'devices': None,
                'message': f'오류 발생: {str(e)}'
            }
    
    def unmount_device(self, device_number):
        """
        마운트된 장치 해제
        
        Args:
            device_number: 해제할 디바이스 번호
            
        Returns:
            dict: 결과 {'success': bool, 'message': str}
        """
        cmd = [
            self.aim_cli_path,
            '--unmount',
            f'--device={device_number}'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            print(f"언마운트 출력:\n{result.stdout}")
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': '언마운트 성공'
                }
            else:
                return {
                    'success': False,
                    'message': f'언마운트 실패: {result.stderr}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'오류 발생: {str(e)}'
            }


def main():
    """
    사용 예제
    """
    # AIM 관리자 초기화
    aim = AIMManager(AIM_CLI_PATH)
    
    # E01 파일 마운트
    e01_file = E01_FILE_PATH
    
    print("=" * 60)
    print("E01 이미지 마운트 시작")
    print("=" * 60)
    
    result = aim.mount_image(
        filename=e01_file,
        readonly=True,
        provider="LibEwf",
        online=True
    )
    
    if result['success']:
        print(f"\n✓ 마운트 성공!")
        if result['device_number'] is not None:
            print(f"✓ 디바이스 번호: {result['device_number']}")
            print(f"✓ 디바이스 경로: \\\\.\\PhysicalDrive{result['device_number']}")
        
        # 마운트된 장치 목록 확인
        print("\n" + "=" * 60)
        print("마운트된 장치 목록 확인")
        print("=" * 60)
        
        list_result = aim.list_devices()
        if list_result['success']:
            print(list_result['devices'])
        
        # 여기서 아티팩트 파싱 작업 수행
        print("\n" + "=" * 60)
        print("아티팩트 파싱 작업을 여기서 수행하세요...")
        print("=" * 60)
        
        # 작업 완료 후 대기
        input("\n아티팩트 파싱이 완료되면 Enter를 눌러 언마운트하세요...")
        
        # 언마운트
        if result['device_number'] is not None:
            print("\n" + "=" * 60)
            print("이미지 언마운트 시작")
            print("=" * 60)
            
            unmount_result = aim.unmount_device(result['device_number'])
            if unmount_result['success']:
                print("✓ 언마운트 성공!")
            else:
                print(f"✗ 언마운트 실패: {unmount_result['message']}")
    else:
        print(f"\n✗ 마운트 실패: {result['message']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
