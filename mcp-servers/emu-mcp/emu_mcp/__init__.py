"""emu-mcp: 케이스가 이미 가진 MCU 펌웨어(ESP32·ESP32-S3·ESP32-C3 전체 플래시 덤프, Arduino AVR Intel HEX)를
PC 에서 실행해 마스킹한 부팅 콘솔을 보여 주고 입력하게 하는 MCP 서버 (등록 이름 pweh-emu, 선택 구성요소).

이 파일은 가볍게 둔다: ``emu_mcp.policy``·``emu_mcp.images``·``emu_mcp.backends`` 를 import 해도 ``server`` (MCP 서버 생성,
콘솔·마스킹 모듈)를 읽지 않게 한다.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
