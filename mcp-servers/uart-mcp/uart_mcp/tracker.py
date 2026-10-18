"""수신 데이터로 콘솔 문맥(uboot / linux-shell / login / password / booting / unknown)을 추적한다.

수신 스레드가 청크마다 ``feed()`` 를 부른다. 완성된 줄마다 부팅 마커·증거·부팅 정보(facts)를 검사하고,
마지막 미완성 줄(= 프롬프트 후보)을 프로필 정규식으로 검사한다.

안전 원칙 (문맥 오판은 분류 오판으로 이어지므로):
- **phase 증거**: U-Boot 증거(``<INTERRUPT>``, ``Unknown command '…' - try 'help'``, autoboot, 배너 …)와
  리눅스 증거(커널 부팅 마커, ``-sh: …: not found``, BusyBox, login …) 중 마지막 것이 phase 를 정한다.
- 프롬프트가 U-Boot/리눅스 정규식 둘 다에 맞거나(``hisilicon # `` 는 리눅스 일반 정규식에도 맞는다) 한쪽에만 맞아도
  phase 증거와 일치하지 않으면 ``unknown`` 으로 둔다 (unknown = 두 분류기의 worst 로 분류 → 더 엄격).
- 프롬프트가 보이지 않으면 문맥은 바뀌지 않는다 (양성 증거로만 바뀐다).
- 여기서 바뀌는 것은 문맥·phase·부팅 정보뿐이다. last_command 같은 안전 상태는 수신 텍스트로 절대 완화하지 않는다.
- **우리 입력의 되풀이는 증거가 아니다**: 세션이 보낸 줄(``note_tx``)의 에코와, 보낸 텍스트를 그대로 되풀이한 출력
  (예: U-Boot 에서 ``echo Linux version 9.9`` → ``Linux version 9.9``)은 phase/부팅/사실 판단에 쓰지 않는다.
  미완성 줄 끝의 입력 에코도 프롬프트·askfirst·login 판단에서 뺀다. 그러지 않으면 에이전트가 보낸 텍스트로 U-Boot 를
  linux-shell 로 오판해 U-Boot 명령(``cp …``)이 리눅스 기준으로 느슨하게 분류된다.
- 이미 U-Boot 프롬프트로 학습한 문자열과 똑같은 프롬프트는 리눅스 phase 증거만으로 linux-shell 로 올리지 않는다(unknown).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .profile import ConsoleProfile
from .textutil import visible_line

# ---------------------------------------------------------------------------
# 내장 증거 정규식 (완성된 줄에 적용)
# ---------------------------------------------------------------------------
UBOOT_EVIDENCE_RE = re.compile(
    r"<INTERRUPT>|Unknown command '[^']*' - try 'help'|^Environment size: \d+/\d+ bytes|^## Error: \"|"
    r"^U-Boot (?:SPL )?\d{4}\.\d{2}|^SF: \d+ bytes @ |^\*\* Too many args|^No SPI flash selected|"
    r"^\d+ KiB \S+ at \d+:\d+ is now current device|^CRC32 for [0-9a-fA-F]+ \.\.\. "
)
LINUX_EVIDENCE_RE = re.compile(
    r"^-?(?:sh|ash|bash|hush): .*(?:not found|Permission denied|can't|No such file)|^BusyBox v\d|^init started: |"
    r"^Linux version \d|^Kernel command line: |^Freeing (?:unused kernel|init) memory|^VFS: Mounted root|"
    r"^Starting kernel|^Uncompressing Linux|Please press Enter to activate this console|^Login incorrect|"
    r"^\[\s*\d+\.\d{3,}\] "
)
# 부팅 시작 증거 (재부팅 → 추적 env 폐기, 문맥 booting). `version` 출력에도 나오는 배너 줄은 쓰지 않는다.
# ("Check Flash Memory Controller" 는 리눅스 커널 드라이버도 같은 문구를 출력하므로 넣지 않는다)
BOOT_START_RE = re.compile(r"^U-Boot SPL|^DRAM:\s+\d|^System startup|^Uncompress Ok")
ASKFIRST_RE = re.compile(r"Please press Enter to activate this console\.?\s*$")
KERNEL_START_RE = re.compile(r"^Starting kernel|^Uncompressing Linux|^Linux version \d|^Booting Linux on physical CPU")
# dump 출력 줄은 마커 검사를 건너뛴다 (성능)
_FAST_SKIP_RE = re.compile(r"^(?:[0-9a-fA-F]{8,16}:? {1,2}[0-9a-fA-F]{2}[ 0-9a-fA-F]|[A-Za-z0-9+/=]{48,}$|\*$)")
# 아직 줄바꿈이 오지 않은 md.b / hexdump -C 출력 줄. ASCII 열이 'foo # ', '|login: ' 처럼 끝나는 순간 수신이 끊기면
# 프롬프트로 오인해(문맥 unknown/login 으로 바뀌거나 명령이 일찍 끝남) 덤프 청크가 깨진다 → 프롬프트 후보에서 뺀다.
_DUMP_TAIL_RE = re.compile(r"^\s*[0-9a-fA-F]{8,16}:? {1,2}[0-9a-fA-F]{2,16}(?: |$)")  # md.b/w/l, hexdump -C
TX_MEMORY = 16  # 되풀이 판단에 쓰는 최근 송신 줄 수
_PARROT_MIN = 4  # 이보다 짧은 수신 줄은 되풀이 검사를 하지 않는다 (증거가 될 만큼 길지 않음)
_ABORT_MARKERS = ("<INTERRUPT>", "^C", "^U")  # U-Boot/리눅스가 Ctrl-C·Ctrl-U 로 버린 입력 에코 뒤에 찍는 표시


def _norm_tx(text: str) -> str:
    """되풀이 비교용 정규화: 따옴표·백슬래시 제거, 공백 하나로 (``echo "Linux version" 9.9`` → ``echo Linux version 9.9``)."""
    return re.sub(r"\s+", " ", re.sub(r"[\"'\\]", "", text)).strip()

# ---------------------------------------------------------------------------
# 부팅 정보(facts) 정규식
# ---------------------------------------------------------------------------
FACT_RES: list[tuple[str, re.Pattern[str]]] = [
    ("uboot_version", re.compile(r"(U-Boot (?!SPL)\d{4}\.\d{2}[^\s(]* \([^)]*\)\S*)")),
    ("spl_version", re.compile(r"(U-Boot SPL \d{4}\.\d{2}[^\s(]* \([^)]*\))")),
    ("dram", re.compile(r"^DRAM:\s+(\d+(?:\.\d+)?\s*[KMG]i?B)")),
    ("relocaddr", re.compile(r"Relocating to ([0-9a-fA-F]{6,16})")),
    ("relocaddr", re.compile(r"Now running in RAM - U-Boot at: ([0-9a-fA-F]{6,16})")),
    ("gd_addr", re.compile(r"new gd at ([0-9a-fA-F]{6,16})")),
    ("sp_addr", re.compile(r"sp at ([0-9a-fA-F]{6,16})")),
    ("sp_addr", re.compile(r"Stack Pointer at: ([0-9a-fA-F]{6,16})")),
    ("malloc_addr", re.compile(r"Reserving \d+k for malloc\(\) at: ([0-9a-fA-F]{6,16})")),
    ("ram_top", re.compile(r"Top of RAM usable for U-Boot at: ([0-9a-fA-F]{6,16})")),
    ("boot_params_addr", re.compile(r"Reserving \d+k for boot params\(\) at: ([0-9a-fA-F]{6,16})")),
    ("flash_detected", re.compile(r"SF: Detected (.+)$")),
    ("flash_geometry", re.compile(r"Block:(\d+[KMG]?)B Chip:(\d+[KMG]?)B Name:\"([^\"]+)\"")),
    ("flash_total_mb", re.compile(r"SPI Nor total size: (\d+)\s*MB")),
    ("flash_current", re.compile(r"(\d+) KiB (\S+) at \d+:\d+ is now current device")),
    ("nand", re.compile(r"^NAND:\s+(\d+(?:\.\d+)?\s*[KMG]i?B)")),
    ("board", re.compile(r"^Board:\s+(.+)$")),
    ("kernel_version", re.compile(r"Linux version (\S+)")),
    ("cmdline", re.compile(r"Kernel command line: (.*)$")),
    ("rootfs", re.compile(r"VFS: Mounted root \((\S+) filesystem\)")),
    ("busybox", re.compile(r"(BusyBox v\d[\w.\-]*(?: \([^)]*\))?)")),
    ("kernel_panic", re.compile(r"Kernel panic - not syncing: (.*)$")),
    ("env_bad_crc", re.compile(r"\*\*\* Warning - bad CRC, using default environment")),
    ("mtd_creating", re.compile(r"Creating (\d+) MTD partitions on \"([^\"]+)\"")),
    ("mtd_part", re.compile(r"^0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+) : \"([^\"]*)\"")),
]
_FACT_KEYWORDS = ("U-Boot", "DRAM", "Reloc", "gd at", "Stack", "malloc", "Top of RAM", "boot params", "SF:", "Block:",
                  "SPI Nor", "KiB", "NAND", "Board", "Linux version", "command line", "VFS", "BusyBox", "panic",
                  "bad CRC", "MTD", "0x")


def extract_facts_from_line(line: str, facts: dict[str, Any]) -> None:
    """한 줄(보이는 형태)에서 부팅 정보를 뽑아 facts 에 반영."""
    if not any(k in line for k in _FACT_KEYWORDS):
        return
    for key, rx in FACT_RES:
        m = rx.search(line)
        if not m:
            continue
        if key == "flash_geometry":
            facts["flash_block"], facts["flash_chip"], facts["flash_name"] = m.group(1), m.group(2), m.group(3)
        elif key == "flash_current":
            facts["flash_current_kib"] = int(m.group(1))
            facts["flash_device"] = m.group(2)
        elif key == "env_bad_crc":
            facts["env_bad_crc"] = True
        elif key == "mtd_creating":
            facts["mtd_device"] = m.group(2)
            facts["mtd_parts"] = []
        elif key == "mtd_part":
            start, end = int(m.group(1), 16), int(m.group(2), 16)
            facts.setdefault("mtd_parts", []).append({"name": m.group(3), "offset": start, "size": end - start})
        elif key == "flash_detected":
            facts["flash_detected"] = m.group(1).strip()
        else:
            facts[key] = m.group(1).strip()


@dataclass
class PromptInfo:
    context: str  # uboot | linux-shell | login | password | unknown
    text: str  # 보이는 프롬프트 문자열
    start: int  # 프롬프트 줄의 절대 시작 오프셋
    end: int  # 절대 끝 오프셋 (이때의 수신 총량)
    kind: str = "prompt"  # prompt | hush_ps2 | askfirst | login | password
    ambiguous: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out = {"context": self.context, "text": self.text, "kind": self.kind, "start": self.start, "end": self.end}
        if self.ambiguous:
            out["ambiguous"] = self.ambiguous
        return out


class ContextTracker:
    """수신 바이트 → 문맥/phase/프롬프트/부팅 정보. 스레드 안전성은 호출자(세션 잠금)가 보장한다."""

    MAX_PARTIAL = 4096

    def __init__(self, profile: ConsoleProfile) -> None:
        self.profile = profile
        self.context = "unknown"
        self.phase = "unknown"  # unknown | uboot | linux
        self.boot_stage: str | None = None
        self.prompt: PromptInfo | None = None  # 지금 수신 끝에 있는 프롬프트 (없으면 None)
        self.last_prompt: PromptInfo | None = None  # 마지막으로 감지한 프롬프트 (이후 입력 에코로 끝에서 밀려났어도 유지)
        self.learned: dict[str, str] = {}
        # U-Boot 프롬프트로 확인(또는 uart_set_context 로 학습)한 적이 있는 모든 문자열 — 추가만 한다.
        # learned["uboot"] 는 덮어쓸 수 있으므로, 리눅스 phase 증거만으로 셸로 올리지 않는 판단은 이 집합으로 한다.
        self.uboot_prompts_seen: set[str] = set()
        self.facts: dict[str, Any] = {}
        self.version = 0  # 문맥이 바뀔 때마다 증가
        self.boot_seq = 0  # 재부팅 증거를 볼 때마다 증가
        self.boot_start_at: int | None = None  # 마지막 부팅 시작 증거 줄의 끝 커서 (boot_seq 가 늘 때 갱신)
        self.autoboot_message: str | None = None
        self.autoboot_at: int | None = None
        self.kernel_at: int | None = None
        self.flash_warnings: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []  # 세션이 꺼내 이벤트 로그에 쓴다
        self._tx_recent: deque[tuple[str, str]] = deque(maxlen=TX_MEMORY)  # (보낸 줄, 정규화)
        self._tx_pending = ""  # 줄 끝 없이 보낸 입력 (기기가 지금 수신 끝에 에코하고 있을 것)
        self._tx_echo = ""  # 방금 보낸 줄(또는 미완성 입력) — 그 에코 줄의 줄바꿈이 오기 전까지 꼬리에서 가린다
        self._partial = ""
        self._partial_overflow = False
        self._line_start = 0
        self._autoboot_this_boot = False
        self._uboot_markers = profile.markers.get("uboot", [])
        self._kernel_markers = [m for m in profile.markers.get("kernel", []) if not m.pattern.startswith("##")]
        self._kernel_load_markers = [m for m in profile.markers.get("kernel", []) if m.pattern.startswith("##")]
        self._user_markers = profile.markers.get("userspace", [])
        self._warn_markers = profile.markers.get("flash_write_warning", [])

    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "phase": self.phase,
            "boot_stage": self.boot_stage,
            "prompt": self.prompt.to_dict() if self.prompt else None,
            "learned_prompts": dict(self.learned),
        }

    def _set_context(self, ctx: str, reason: str, at: int) -> None:
        if ctx != self.context:
            self.events.append({"type": "context", "from": self.context, "to": ctx, "reason": reason, "cursor": at})
            self.context = ctx
            self.version += 1

    def _set_phase(self, phase: str, reason: str, at: int) -> None:
        if phase != self.phase:
            self.events.append({"type": "phase", "from": self.phase, "to": phase, "reason": reason, "cursor": at})
            self.phase = phase
            self.version += 1

    def set_phase_evidence(self, phase: str, reason: str, at: int) -> None:
        """외부(도구) 증거로 phase 를 정한다 (예: Ctrl-C 응답에 <INTERRUPT> 없음 + 리눅스 프롬프트)."""
        self._set_phase(phase, reason, at)
        self._evaluate_tail(at, at)

    # ------------------------------------------------------------------
    def note_tx(self, lines: list[str], pending: str, discarded: str = "") -> None:
        """세션이 방금 보낸 완성 줄과 남은 미완성 입력 (쓰기 직전에 호출 — 에코보다 먼저).

        discarded: 이번 송신(Ctrl-C/Ctrl-U 등)으로 버려지는 이전 미완성 입력 — 그 에코는 ``…<INTERRUPT>`` 줄에 남는다.
        """
        for ln in [discarded, *lines]:
            t = visible_line(ln).strip()
            if len(t) >= 3:
                self._tx_recent.append((t, _norm_tx(t)))
        self._tx_pending = visible_line(pending)
        self._tx_echo = self._tx_pending or (visible_line(lines[-1]).strip() if lines else "")

    def _strip_tx_line(self, line: str) -> str:
        """완성된 수신 줄에서 우리 입력의 되풀이를 뺀 '증거용' 텍스트. 줄 전체가 되풀이면 ''."""
        if not self._tx_recent:
            return line
        r = line.rstrip()
        marker = next((m for m in _ABORT_MARKERS if r.endswith(m)), "")  # Ctrl-C 로 버린 입력의 에코 뒤에 붙는 표시
        body = r[: len(r) - len(marker)]
        for t, _ in reversed(self._tx_recent):
            if body.endswith(t):  # 에코 줄: 프롬프트 + 보낸 명령 (Ctrl-C 면 + <INTERRUPT>/^C — 표시는 진짜 증거라 남긴다)
                r = body[: len(body) - len(t)] + marker
                break
        core = r.strip()
        if len(core) >= _PARROT_MIN:
            nc = _norm_tx(core)
            for t, nt in self._tx_recent:
                if core in t or (nc and nc in nt):  # echo/printf 처럼 보낸 텍스트를 그대로 되풀이한 출력
                    return ""
        return r

    def _mask_tx_tail(self, tail: str) -> str:
        """미완성 줄 끝에 보이는 입력 에코를 공백으로 가린다 (프롬프트 + 입력은 프롬프트가 아니다).

        - 줄 끝 없이 보낸 입력의 에코 전체 (``hisilicon # echo login: ``)
        - 방금 보낸 줄의 에코가 줄바꿈 전까지 한 글자씩 오는 동안의 앞부분 (``hisilicon # echo Please press En…``)
        """
        p = self._tx_pending
        if p and tail.endswith(p):
            return tail[: len(tail) - len(p)] + " " * len(p)
        e = self._tx_echo
        if e:
            for k in range(min(len(e), len(tail)), 0, -1):
                if tail.endswith(e[:k]):
                    return tail[: len(tail) - k] + " " * k
        return tail

    # ------------------------------------------------------------------
    def feed(self, data: bytes, base: int) -> None:
        text = data.decode("latin-1")
        end = base + len(data)
        pos = 0
        while True:
            nl = text.find("\n", pos)
            if nl < 0:
                break
            if self._partial_overflow:
                line = self._partial
            else:
                line = self._partial + text[pos:nl]
            self._on_line(line, base + nl + 1)
            self._tx_echo = ""  # 에코 줄이 끝났다 (이후 꼬리는 명령 출력/프롬프트)
            self._partial = ""
            self._partial_overflow = False
            self._line_start = base + nl + 1
            pos = nl + 1
        rest = text[pos:]
        if rest:
            if len(self._partial) + len(rest) > self.MAX_PARTIAL:
                self._partial = (self._partial + rest)[-self.MAX_PARTIAL:]
                self._partial_overflow = True
            else:
                self._partial += rest
        self._evaluate_tail(end, base)

    # ------------------------------------------------------------------
    def _on_line(self, raw: str, end_abs: int) -> None:
        line = visible_line(raw)
        if not line:
            return
        if len(line) > 40 and _FAST_SKIP_RE.match(line):
            return
        line = self._strip_tx_line(line)
        if not line.strip():
            return  # 우리 입력의 에코/되풀이뿐 — 증거·사실로 쓰지 않는다
        extract_facts_from_line(line, self.facts)
        if BOOT_START_RE.search(line):
            self._on_boot_start(line, end_abs)
        weak_uboot = self.boot_stage not in ("kernel", "userspace") and any(m.search(line) for m in self._uboot_markers)
        if weak_uboot or UBOOT_EVIDENCE_RE.search(line):
            self._set_phase("uboot", f"U-Boot 증거: {line[:80]}", end_abs)
            if self.context in ("linux-shell", "login", "password"):
                self._set_context("unknown", "U-Boot 증거가 나옴", end_abs)
        for m in self._kernel_load_markers:
            if m.search(line):
                self.boot_stage = "kernel-load"
        if any(m.search(line) for m in self._kernel_markers) or KERNEL_START_RE.search(line):
            if self.kernel_at is None or self.boot_stage not in ("kernel", "userspace"):
                self.kernel_at = end_abs
            self.boot_stage = "kernel"
            self._set_phase("linux", f"커널 부팅: {line[:80]}", end_abs)
            self._set_context("booting", "커널 부팅 마커", end_abs)
        elif any(m.search(line) for m in self._user_markers) or LINUX_EVIDENCE_RE.search(line):
            self._set_phase("linux", f"리눅스 증거: {line[:80]}", end_abs)
            if self.boot_stage == "kernel":
                self.boot_stage = "userspace"
            if self.context == "uboot":
                self._set_context("unknown", "리눅스 증거가 나옴", end_abs)
        for m in self._warn_markers:
            if m.search(line):
                ev = {"type": "flash_write_warning", "line": line[:200], "cursor": end_abs}
                self.flash_warnings.append(ev)
                self.events.append(ev)
                break
        if not self._autoboot_this_boot and any(m.search(line) for m in self.profile.autoboot):
            self._on_autoboot(raw, end_abs)

    def _on_boot_start(self, line: str, at: int) -> None:
        # 같은 부팅의 연속된 시작 줄(System startup → DRAM: …)은 한 번만 센다
        if self.boot_stage != "uboot":
            self.boot_seq += 1
            self.boot_start_at = at
            self._autoboot_this_boot = False
            self.autoboot_message = None
            self.kernel_at = None
            self.events.append({"type": "boot_start", "line": line[:120], "cursor": at, "boot_seq": self.boot_seq})
        self.boot_stage = "uboot"
        self._set_phase("uboot", "부팅 시작", at)
        self._set_context("booting", f"부팅 시작: {line[:60]}", at)

    def _on_autoboot(self, raw: str, at: int) -> None:
        # 카운트다운은 \b\b\b 로 숫자를 덮어쓰므로 첫 백스페이스 앞(= 처음 출력한 bootdelay)을 쓴다
        first = visible_line(raw.split("\x08", 1)[0]) or visible_line(raw)
        if self.boot_stage != "uboot":
            # 부팅 시작 줄(DRAM:/SPL …)을 못 본 부팅: autoboot 메시지도 재부팅 증거다
            self.boot_seq += 1
            self.boot_start_at = at
            self.kernel_at = None
            self.events.append({"type": "boot_start", "line": first[:120], "cursor": at, "boot_seq": self.boot_seq})
        self._autoboot_this_boot = True
        self.autoboot_message = first.strip()
        self.autoboot_at = at
        m = re.search(r"(\d+)\s*$", first) or re.search(r":\s*(\d+)", first)
        if m:
            self.facts["bootdelay_seen"] = int(m.group(1))
        self.facts["autoboot_message"] = self.autoboot_message
        self.boot_stage = "autoboot"
        self._set_phase("uboot", "autoboot 메시지", at)
        self._set_context("booting", "autoboot 카운트다운", at)
        self.events.append({"type": "autoboot", "message": self.autoboot_message, "cursor": at})

    # ------------------------------------------------------------------
    def _match_any(self, patterns: list[re.Pattern[str]], text: str) -> bool:
        return any(p.search(text) for p in patterns)

    def _evaluate_tail(self, end: int, base: int) -> None:
        if self._partial_overflow:
            self.prompt = None
            return
        tail = self._mask_tx_tail(visible_line(self._partial))
        if not tail.strip():
            self.prompt = None
            return
        start = self._line_start
        # autoboot 은 줄바꿈 없이 카운트다운하므로 미완성 줄에서도 검사
        if not self._autoboot_this_boot and len(tail) < 300 and self._match_any(self.profile.autoboot, tail):
            self._on_autoboot(self._partial, end)
        if len(tail) > 200 or _DUMP_TAIL_RE.match(tail):
            self.prompt = None
            return
        if ASKFIRST_RE.search(tail):
            self._set_phase("linux", "askfirst", end)
            self.prompt = self.last_prompt = PromptInfo("login", tail, start, end, "askfirst")
            self._set_context("login", "askfirst 콘솔 활성화 대기", end)
            return
        if self._match_any(self.profile.password_prompts, tail):
            self.prompt = self.last_prompt = PromptInfo("password", tail, start, end, "password")
            self._set_context("password", "비밀번호 프롬프트", end)
            return
        if self._match_any(self.profile.login_prompts, tail):
            self._set_phase("linux", "login 프롬프트", end)
            self.facts["login_prompt"] = tail
            self.prompt = self.last_prompt = PromptInfo("login", tail, start, end, "login")
            self._set_context("login", "login 프롬프트", end)
            return
        is_u = self._match_any(self.profile.uboot_prompts, tail) or tail == self.learned.get("uboot")
        is_l = self._match_any(self.profile.linux_prompts, tail) or tail == self.learned.get("linux-shell")
        is_ps2 = self._match_any(self.profile.hush_ps2, tail)
        if not (is_u or is_l or is_ps2):
            self.prompt = None
            return
        if is_ps2 and not (is_u or is_l):
            ctx = {"uboot": "uboot", "linux": "linux-shell"}.get(self.phase, "unknown")
            self.prompt = self.last_prompt = PromptInfo(ctx, tail, start, end, "hush_ps2")
            self._set_context(ctx, "보조 프롬프트(PS2)", end)
            return
        cands = [c for c, ok in (("uboot", is_u), ("linux-shell", is_l)) if ok]
        if self.phase == "uboot" and is_u:
            ctx = "uboot"
        elif self.phase == "linux" and is_l and not (is_u and tail in self.uboot_prompts_seen):
            # U-Boot 프롬프트로 확인한 적이 있는 문자열은 리눅스 phase 증거만으로 셸로 올리지 않는다 (증거가 위조됐을 수 있음)
            ctx = "linux-shell"
        else:
            ctx = "unknown"
        info = PromptInfo(ctx, tail, start, end, "prompt", cands if ctx == "unknown" else [])
        self.prompt = self.last_prompt = info
        if ctx in ("uboot", "linux-shell"):
            self.learned[ctx] = tail
            if ctx == "linux-shell":
                self.facts["shell_prompt"] = tail
            else:
                self.facts["uboot_prompt"] = tail
                self.uboot_prompts_seen.add(tail)
            if self.boot_stage in ("autoboot", "uboot", "kernel-load") and ctx == "uboot":
                self.boot_stage = None
            if ctx == "linux-shell":
                self.boot_stage = None
        reason = f"프롬프트 {tail!r} (phase={self.phase})"
        self._set_context(ctx, reason, end)

    # ------------------------------------------------------------------
    def tail_text(self) -> str:
        return visible_line(self._partial) if not self._partial_overflow else ""

    def line_start(self) -> int:
        return self._line_start

    def drain_events(self) -> list[dict[str, Any]]:
        ev, self.events = self.events, []
        return ev
