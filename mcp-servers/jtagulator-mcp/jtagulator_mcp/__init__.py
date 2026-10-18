"""jtagulator-mcp: JTAGulator(USB-시리얼 텍스트 메뉴) 핀아웃 스캔 MCP 서버 (pweh-jtagulator).

모듈:
- protocol : 펌웨어 프로토콜 상수, 장치 상태 판별, 입력 해석 규칙, 순열/검증
- classify : JTAGulator 키 입력 위험도 분류기 (pweh.safety.Classification)
- driver   : 시리얼 링크·세션 기록·안전 가드·대화 엔진·스캔 감시
- parsers  : 스캔 출력 파서와 결과 요약 (JTAG 핀아웃, IDCODE, UART, TXD)
- jep106   : IDCODE 해석과 JEP106 제조사 선별 목록
- sim      : 펌웨어 충실 시뮬레이터 (TCP/PTY)
- server   : MCP 도구
"""
