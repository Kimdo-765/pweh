"""PWEH (Play With Every Hardware) 공통 코어.

에이전트가 MCP 서버와 Skill을 통해 임베디드 기기(CCTV/IoT)를 분석할 때
모든 서버가 공유하는 계약을 제공한다.

- config: pipeline-config.yaml 로딩, 대상 기기 프로필
- case: 케이스(분석 작업) 작업공간, 아티팩트/단계 결과/발견사항 저장
- safety: 명령 위험도 분류, 서버 측 안전 게이트, 사람 승인(approval)
- jobs: 오래 걸리는 작업(플래시 덤프 등)의 백그라운드 실행
- mcpkit: MCP 서버 공통 헬퍼
- report: 발견사항 → Markdown 보고서
"""

__version__ = "0.1.0"
