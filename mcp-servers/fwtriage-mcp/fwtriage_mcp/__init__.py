"""fwtriage-mcp: 오프라인 펌웨어 트리아지 MCP 서버 (pweh-fwtriage).

순수 Python(+PyYAML)으로 펌웨어 덤프의 시그니처/엔트로피/U-Boot env/파티션/uImage·FIT/squashfs 추출(unsquashfs)/
ELF/rootfs 감사/문자열 휴리스틱/기본 비밀번호 해시 대조를 수행한다. REA(binwalk/unblob/Ghidra)를 보완한다.
"""
