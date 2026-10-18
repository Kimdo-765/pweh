"""카메라 UART 콘솔 시뮬레이터와 합성 펌웨어 빌더 (``pweh.mocktarget``).

모든 UART 테스트, 종단 간(e2e) 테스트, 데모 예제가 이 시뮬레이터를 대상으로 동작한다.

- ``MockDevice``     : PTY/TCP 로 접속하는 가상 IP 카메라 (부트ROM → U-Boot → 리눅스 → BusyBox)
- ``build_image``    : 프로필의 mtdparts 배치대로 16MiB SPI NOR 합성 펌웨어 + 매니페스트(정답 포함) 생성
- ``load_profile``   : 시뮬레이터 프로필 로드 (이름/경로/딕셔너리 + overrides)
- ``list_profiles``  : 내장 프로필 목록

콘솔 스크립트: ``pweh-mock-device`` (``pweh.mocktarget.cli``).
"""

from .device import STATES, MockDevice
from .firmware import build_image, build_image_bytes
from .profiles import SYNTHETIC_MARKER, list_profiles, load_profile

__all__ = ["MockDevice", "STATES", "SYNTHETIC_MARKER", "build_image", "build_image_bytes", "list_profiles", "load_profile"]
