"""패턴 팩 로더 (src/pweh/data/<팩>-hunt-patterns.yaml).

팩 (PACKS, 고정 목록):
- cctv (기본): cctv-hunt-patterns.yaml (원본: docs/references/cctv-hunt-patterns.yaml). fw_strings_hunt 기본값,
  fw_rootfs_audit·fw_elf_info·fw_crack_hashes 가 쓰는 credential_patterns/function_heuristics/known_hashes 도 이 팩에만 있다.
- game: game-hunt-patterns.yaml. fw_strings_hunt(patterns="game" / "game:<선택자>") 의 string_heuristics 만 있다.
두 팩은 한 호출에서 섞지 않는다 (split_pack_spec).

YAML 의 notes 에 정의된 의미를 그대로 따른다:
- 정규식: Python re, re.MULTILINE 으로 컴파일 (^/$ 는 줄 단위), (?i) 가 붙은 것만 대소문자 무시
- scope: strings = 바이너리에서 뽑은 인쇄 가능 ASCII 문자열(strings -n 4 상당)의 각 줄,
         text = 텍스트 파일(스크립트/설정/JS/HTML)의 각 줄,
         raw = 파일 전체 바이트 (pattern.encode('latin-1') 로 만든 bytes 정규식, \\xHH 이스케이프),
         any = strings + text
- credential_patterns.files / interesting_paths: rootfs 루트 기준 POSIX glob ('**' = 0개 이상 디렉터리)

알 수 없는 키는 무시하고, 컴파일되지 않는 정규식은 errors 에 기록한다 (로더가 죽지 않게).
성능: 각 정규식에서 '반드시 나타나야 하는 리터럴' 후보를 보수적으로 뽑아(sre 파서) 말뭉치에 없으면 건너뛴다.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pweh.errors import ValidationFailed

try:  # Python 3.11+ 에서 sre_parse 는 re._parser 로 이동
    import re._parser as _sre_parse  # type: ignore[import-not-found]
    import re._constants as _sre_c  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - 3.10
    import sre_constants as _sre_c  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

log = logging.getLogger("pweh.fwtriage")

DATA_FILE_NAME = "cctv-hunt-patterns.yaml"
DEFAULT_PACK = "cctv"
#: 패턴 팩 이름 → src/pweh/data 아래 파일 이름. 고정 목록이다 — 팩 이름으로 경로를 만들지 않는다.
PACKS: dict[str, str] = {"cctv": DATA_FILE_NAME, "game": "game-hunt-patterns.yaml"}
#: 어느 팩과도 함께 쓸 수 있는 사용자 패턴 접두사
CUSTOM_PREFIXES = ("re:", "raw:", "lit:")

# YAML category → finding.schema.json category (YAML notes 의 매핑 규칙)
FINDING_CATEGORY = {
    "crypto": "weak-crypto",
    "memory-safety": "memory-corruption",
    "path-traversal": "info-leak",
    "session-token": "auth-bypass",
}
FINDING_CATEGORIES = {"auth-bypass", "hardcoded-credential", "backdoor", "command-injection", "debug-interface", "weak-crypto", "info-leak", "insecure-update", "memory-corruption", "insecure-default", "other"}
# auth-hunt.schema.json vendor_family 매핑
VENDOR_FAMILY = {"hikvision": "hikvision-like", "dahua": "dahua-like", "xiongmai": "xiongmai-like", "hisilicon_video_encoder": "hisilicon-oem"}


def finding_category(cat: str | None) -> str:
    c = str(cat or "other")
    c = FINDING_CATEGORY.get(c, c)
    return c if c in FINDING_CATEGORIES else "other"


def pack_name(pack: Any = None) -> str:
    """팩 이름 정규화·검증 (None/빈 문자열 = 기본 cctv 팩). 알 수 없는 팩이면 ValidationFailed."""
    if pack is None or (isinstance(pack, str) and not pack.strip()):
        return DEFAULT_PACK
    name = str(pack).strip().lower()
    if name not in PACKS:
        raise ValidationFailed(f"알 수 없는 패턴 팩: {pack!r}", hint=f"사용 가능한 팩: {', '.join(PACKS)}")
    return name


def data_file_path(pack: str = DEFAULT_PACK) -> Path:
    import pweh.data as _data

    return Path(_data.__file__).resolve().parent / PACKS[pack_name(pack)]


def split_pack_spec(spec: Any) -> tuple[str, Any]:
    """fw_strings_hunt 의 patterns 인자 → (팩 이름, 그 팩의 PatternSet.select 에 넘길 선택자).

    - 기본이 아닌 팩(지금은 'game')의 이름이나 '<팩>:<선택자>' 가 하나라도 있으면 그 팩이다:
      '<팩>' → 팩 전체, '<팩>:<x>' → x(id/category/vendor/severity/'<접두사>*'), 사용자 패턴(re:/raw:/lit:)은 그대로.
      접두사 없는 다른 선택자('cctv', 'xm-*', 일반 단어)는 CCTV 팩 문법이라 섞을 수 없다 → ValidationFailed.
    - 그 밖에는 기본(cctv) 팩이고 spec 을 손대지 않고 돌려준다 (기존 동작 그대로).
    """
    items = [] if spec is None else ([spec] if isinstance(spec, str) else list(spec))
    others = [p for p in PACKS if p != DEFAULT_PACK]

    def pack_of(item: Any) -> str | None:
        low = str(item).strip().lower()
        return next((p for p in others if low == p or low.startswith(p + ":")), None)

    named = sorted({p for p in map(pack_of, items) if p})
    if not named:
        return DEFAULT_PACK, spec
    if len(named) > 1:
        raise ValidationFailed(f"한 호출에서 여러 패턴 팩을 섞을 수 없습니다: {', '.join(named)}", hint="팩마다 따로 호출하세요.")
    pack = named[0]
    local: list[str] = []
    mixed: list[str] = []
    for raw_item in items:
        item = str(raw_item).strip()
        if not item:
            continue
        low = item.lower()
        if low == pack:
            local.append(pack)
        elif low.startswith(pack + ":"):
            sel = item[len(pack) + 1 :].strip()
            if not sel:
                raise ValidationFailed(f"'{item}' 뒤에 선택자가 없습니다.", hint=f"'{pack}'(팩 전체) 또는 '{pack}:<category|id|vendor|접두사*>' 를 쓰세요.")
            local.append(sel)
        elif low.startswith(CUSTOM_PREFIXES):
            local.append(item)
        else:
            mixed.append(item)
    if mixed:
        raise ValidationFailed(
            f"{pack} 팩 선택과 다른 팩의 선택자를 한 호출에서 섞을 수 없습니다: {', '.join(repr(m) for m in mixed[:5])}",
            hint=f"{pack} 팩 안에서 고르려면 '{pack}:<category|id|vendor|접두사*>', 문자열 그대로 찾으려면 'lit:<문자열>' 을 쓰고, "
            "CCTV 팩 선택자는 따로 호출하세요.",
        )
    return pack, local


# ---------------------------------------------------------------------------
# 필수 리터럴 추출 (보수적: 확실하지 않으면 None → 필터 없음)
# ---------------------------------------------------------------------------

_MIN_LIT = 3


def _req(seq: Any, ignorecase: bool) -> list[str] | None:
    """seq(sre 파싱 결과)가 일치하려면 반드시 포함해야 하는 리터럴들 중 '하나 이상'(OR 집합). 모르면 None."""
    best: list[str] | None = None
    run: list[str] = []

    def consider(cands: list[str] | None) -> None:
        nonlocal best
        if not cands:
            return
        score = min(len(c) for c in cands)
        if score < _MIN_LIT:
            return
        if best is None or score > min(len(c) for c in best) or (score == min(len(c) for c in best) and len(cands) < len(best)):
            best = cands

    def flush() -> None:
        if run:
            consider(["".join(run)])
            run.clear()

    for op, av in seq:
        if op is _sre_c.LITERAL:
            ch = chr(av)
            run.append(ch.lower() if ignorecase else ch)
            continue
        if op is _sre_c.AT:
            continue  # 0폭 단언은 리터럴 연속을 끊지 않는다 (\b, ^, $)
        flush()
        if op is _sre_c.SUBPATTERN:
            sub = av[-1]
            add_flags = av[1] if len(av) >= 4 else 0
            del_flags = av[2] if len(av) >= 4 else 0
            ic = ignorecase
            if add_flags & _sre_c.SRE_FLAG_IGNORECASE:
                ic = True
            if del_flags & _sre_c.SRE_FLAG_IGNORECASE:
                ic = False
            if ic != ignorecase:
                # 범위 플래그((?i:...)/(?-i:...))로 대소문자 모드가 바뀐 구간의 리터럴은 사전 필터(전역 플래그 기준 비교)로
                # 표현할 수 없다 → 정보 없음으로 둔다. (예: 're:(?i:secret)' 의 'secret' 을 대소문자 구분으로 비교하면 'SECRET' 을 놓친다)
                continue
            consider(_req(sub, ic))
        elif op is _sre_c.BRANCH:
            alts: list[str] = []
            ok = True
            for b in av[1]:
                r = _req(b, ignorecase)
                if not r:
                    ok = False
                    break
                alts.extend(r)
            if ok:
                consider(sorted(set(alts)))
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT, getattr(_sre_c, "POSSESSIVE_REPEAT", object())):
            mn, mx, item = av
            if mn >= 1:
                consider(_req(item, ignorecase))
        elif op is getattr(_sre_c, "ATOMIC_GROUP", object()):
            consider(_req(av, ignorecase))
        # IN, ANY, NOT_LITERAL, ASSERT, GROUPREF 등: 리터럴 정보 없음 (연속만 끊음)
    flush()
    return best


def required_literals(pattern: str) -> tuple[list[str] | None, bool]:
    """(리터럴 OR 집합 또는 None, ignorecase 여부)."""
    try:
        parsed = _sre_parse.parse(pattern, 0)
    except Exception:
        return None, False
    flags = parsed.state.flags if hasattr(parsed, "state") else getattr(parsed, "pattern").flags
    ic = bool(flags & _sre_c.SRE_FLAG_IGNORECASE)
    try:
        lits = _req(list(parsed), ic)
    except Exception:
        return None, ic
    return lits, ic


# ---------------------------------------------------------------------------
# 데이터 구조
# ---------------------------------------------------------------------------


@dataclass
class StringHeuristic:
    id: str
    pattern: str
    category: str
    severity: str
    scope: str
    vendor: str
    rationale: str = ""
    references: list[str] = field(default_factory=list)
    rx: re.Pattern[str] | None = None
    rx_bytes: re.Pattern[bytes] | None = None
    literals: list[str] | None = None
    ignorecase: bool = False
    custom: bool = False

    def finding_category(self) -> str:
        return finding_category(self.category)

    def applies(self, scope: str) -> bool:
        if self.scope == "any":
            return scope in ("strings", "text")
        return self.scope == scope

    def prefilter(self, corpus: str, corpus_lower: Any) -> bool:
        if not self.literals:
            return True
        if self.ignorecase:
            low = corpus_lower()
            return any(lit in low for lit in self.literals)
        return any(lit in corpus for lit in self.literals)

    def brief(self) -> dict[str, Any]:
        return {"id": self.id, "category": self.category, "severity": self.severity, "scope": self.scope, "vendor": self.vendor}


@dataclass
class CredentialPattern:
    id: str
    files: list[str]
    pattern: str
    category: str
    severity: str
    rationale: str
    references: list[str]
    rx: re.Pattern[str] | None
    file_rx: list[re.Pattern[str]]
    candidate_passwords: list[str]


@dataclass
class PatternSet:
    source: str
    sha256: str
    version: Any
    string_heuristics: list[StringHeuristic]
    credential_patterns: list[CredentialPattern]
    function_heuristics: list[dict[str, Any]]
    web_server_binaries: dict[str, list[str]]
    interesting_paths: list[str]
    interesting_rx: list[tuple[str, re.Pattern[str]]]
    notes: list[str]
    errors: list[str]
    known_hashes: dict[str, dict[str, Any]]
    candidate_passwords: list[str]
    pack: str = DEFAULT_PACK

    def categories(self) -> list[str]:
        return sorted({h.category for h in self.string_heuristics})

    def web_binary_vendor(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for vendor, names in self.web_server_binaries.items():
            for n in names:
                out.setdefault(str(n), vendor)
        return out

    def select(self, spec: Any, *, min_severity: str | None = None, strict: bool = False) -> tuple[list[StringHeuristic], list[str]]:
        """patterns 인자 해석: '<팩 이름>'(cctv 팩이면 'cctv')/'all'/'default' = 전체, 목록이면 id/category/vendor/severity 선택자 또는
        're:<정규식>'(scope any), 'raw:<정규식>'(바이트), 'lit:<문자열>' 사용자 패턴. 일치하는 선택자가 없는 일반
        문자열은 대소문자 무시 리터럴로 취급한다. strict=True(기본이 아닌 팩, split_pack_spec 뒤)면 리터럴로 바꾸지 않고
        ValidationFailed — 'game:<오타>' 가 조용히 리터럴 검색이 되지 않게."""
        notes: list[str] = []
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        whole = (self.pack, "all", "default")
        if spec is None or spec == "" or (isinstance(spec, str) and spec.lower() in whole):
            chosen = list(self.string_heuristics)
        else:
            items = [spec] if isinstance(spec, str) else list(spec)
            chosen = []
            seen: set[str] = set()
            for raw_item in items:
                item = str(raw_item).strip()
                if not item:
                    continue
                low = item.lower()
                if low in whole:
                    sel = list(self.string_heuristics)
                elif low.startswith(("re:", "raw:", "lit:")):
                    kind, body = item.split(":", 1)
                    h = make_custom(custom_id(kind.lower(), body), body, kind.lower())
                    if h is None:
                        notes.append(f"사용자 패턴을 컴파일할 수 없음: {item[:80]}")
                        continue
                    if matches_empty(h):
                        # 빈 문자열과 일치하면 모든 위치가 히트가 되어(수백만 건) 메모리·시간만 쓰고 의미가 없다
                        notes.append(f"빈 문자열과도 일치하는 사용자 패턴은 모든 위치에서 일치하므로 건너뜁니다: {item[:80]}")
                        continue
                    sel = [h]
                else:
                    sel = [h for h in self.string_heuristics if low in (h.id.lower(), h.category.lower(), h.vendor.lower(), h.severity.lower()) or h.id.lower().startswith(low.rstrip("*")) and low.endswith("*")]
                    if not sel and strict:
                        raise ValidationFailed(
                            f"'{self.pack}:{item}' 와 일치하는 {self.pack} 팩 휴리스틱이 없습니다 (id/category/vendor/severity 또는 '<접두사>*').",
                            hint=f"{self.pack} 팩 category: {', '.join(self.categories())}. 목록은 fw_hunt_patterns(pack='{self.pack}'), "
                            "문자열 그대로 찾으려면 'lit:<문자열>'.",
                        )
                    if not sel:
                        h = make_custom(custom_id("lit", item), item, "lit")
                        sel = [h] if h else []
                        notes.append(f"'{item}' 는 알려진 id/category/vendor 가 아니어서 대소문자 무시 리터럴로 검색합니다.")
                for h in sel:
                    if h.id not in seen:
                        seen.add(h.id)
                        chosen.append(h)
        if min_severity:
            lim = sev_rank.get(min_severity, 4)
            chosen = [h for h in chosen if sev_rank.get(h.severity, 4) <= lim]
        return chosen, notes


def matches_empty(h: StringHeuristic) -> bool:
    """빈 문자열과 일치하는 패턴인지 ('lit:', 're:a*', 're:.*' 등)."""
    try:
        if h.rx_bytes is not None:
            return h.rx_bytes.search(b"") is not None
        return h.rx is not None and h.rx.search("") is not None
    except re.error:  # pragma: no cover - 컴파일된 패턴이라 실제로는 없음
        return True


def custom_id(kind: str, body: str) -> str:
    """사용자 패턴의 check id: ``custom-<lit|re|raw>-<sha256 앞 8자>``.

    실행 순서·호출과 무관하게 같은 패턴이면 같은 id 라서 여러 fw_strings_hunt 결과의 checks[] 를 합쳐도
    서로 다른 패턴이 같은 id 로 겹치지 않는다. lit 은 대소문자 무시 검색이므로 소문자로 정규화해 계산한다
    (선택자에 맞지 않아 리터럴로 바뀐 일반 단어도 'lit:<단어>' 와 같은 id)."""
    key = body.lower() if kind == "lit" else body
    digest = hashlib.sha256((kind + "\x00" + key).encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"custom-{kind}-{digest}"


def make_custom(hid: str, body: str, kind: str) -> StringHeuristic | None:
    # 해시 id 만으로는 무엇을 찾았는지 알 수 없으므로 rationale(= checks[].description)에 패턴 원문을 넣는다
    shown = body if len(body) <= 120 else body[:119] + "…"
    try:
        if kind == "lit":
            pat = "(?i)" + re.escape(body)
            rx = re.compile(pat, re.MULTILINE)
            return StringHeuristic(hid, pat, "custom", "info", "any", "custom", rationale=f"사용자 지정 리터럴: {shown}", rx=rx, literals=[body.lower()] if len(body) >= _MIN_LIT else None, ignorecase=True, custom=True)
        if kind == "raw":
            rxb = re.compile(body.encode("latin-1"), re.MULTILINE)
            return StringHeuristic(hid, body, "custom", "info", "raw", "custom", rationale=f"사용자 지정 바이트 정규식: {shown}", rx_bytes=rxb, custom=True)
        rx = re.compile(body, re.MULTILINE)
        lits, ic = required_literals(body)
        return StringHeuristic(hid, body, "custom", "info", "any", "custom", rationale=f"사용자 지정 정규식: {shown}", rx=rx, literals=lits, ignorecase=ic, custom=True)
    except (re.error, UnicodeEncodeError, ValueError):
        return None


def glob_to_regex(glob: str) -> re.Pattern[str]:
    """rootfs 상대 POSIX glob → 정규식 ('**/' = 0개 이상 디렉터리, '*' = 한 경로 요소 안)."""
    g = glob.lstrip("/")
    out = []
    i = 0
    while i < len(g):
        c = g[i]
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = g.find("]", i + 1)
            if j < 0:
                out.append(re.escape(c))
                i += 1
            else:
                cls = g[i + 1 : j].replace("\\", "\\\\")
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append(f"[{cls}]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


_KNOWN_HASH_RE = re.compile(r"^\^(?P<user>[A-Za-z0-9_.-]+):(?P<hash>.+?):$")


def _unescape_regex_literal(s: str) -> str | None:
    """'\\$1\\$/5bW...' 같은 단순 이스케이프 리터럴 → 문자열. 정규식 메타문자가 남으면 None."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        if c in ".^$*+?{}[]|()":
            return None
        out.append(c)
        i += 1
    return "".join(out)


_CACHE: dict[tuple[str, str], tuple[float, PatternSet]] = {}
_CACHE_LOCK = threading.Lock()


def load_patterns(path: str | Path | None = None, *, pack: str = DEFAULT_PACK) -> PatternSet:
    """패턴 팩 로드 (팩·파일별 캐시, 파일 mtime 이 바뀌면 다시 읽는다).

    load_patterns() 는 예전과 같은 CCTV 팩이다. pack='game' 은 game-hunt-patterns.yaml. path 를 주면 그 파일을
    pack 이름(전체 선택 키워드 등)으로 읽는다. 알 수 없는 pack 은 ValidationFailed.
    """
    name = pack_name(pack)
    p = Path(path) if path else data_file_path(name)
    key = (name, str(p))
    try:
        mtime = p.stat().st_mtime
    except OSError:
        mtime = -1.0
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
    ps = _load(p, name)
    with _CACHE_LOCK:
        _CACHE[key] = (mtime, ps)
    return ps


def _load(p: Path, pack: str = DEFAULT_PACK) -> PatternSet:
    errors: list[str] = []
    raw_bytes = b""
    data: dict[str, Any] = {}
    try:
        raw_bytes = p.read_bytes()
        loaded = yaml.safe_load(raw_bytes.decode("utf-8")) or {}
        if isinstance(loaded, dict):
            data = loaded
        else:
            errors.append("최상위가 매핑이 아님")
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        errors.append(f"패턴 파일을 읽을 수 없음: {exc}")
    sh: list[StringHeuristic] = []
    for i, item in enumerate(data.get("string_heuristics") or []):
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("pattern"), str):
            errors.append(f"string_heuristics[{i}] 형식 오류")
            continue
        scope = str(item.get("scope") or "any").lower()
        if scope not in ("any", "text", "strings", "raw"):
            errors.append(f"{item['id']}: 알 수 없는 scope {scope!r} → any")
            scope = "any"
        h = StringHeuristic(
            id=str(item["id"]), pattern=item["pattern"], category=str(item.get("category") or "other"),
            severity=str(item.get("severity_hint") or item.get("severity") or "info").lower(), scope=scope,
            vendor=str(item.get("vendor") or "generic"), rationale=str(item.get("rationale") or ""),
            references=[str(r) for r in (item.get("references") or [])],
        )
        try:
            if scope == "raw":
                h.rx_bytes = re.compile(h.pattern.encode("latin-1"), re.MULTILINE)
                lits, ic = required_literals(h.pattern)
            else:
                h.rx = re.compile(h.pattern, re.MULTILINE)
                lits, ic = required_literals(h.pattern)
                h.literals, h.ignorecase = lits, ic
        except (re.error, UnicodeEncodeError) as exc:
            errors.append(f"{h.id}: 정규식 컴파일 실패: {exc}")
            continue
        sh.append(h)
    cps: list[CredentialPattern] = []
    known: dict[str, dict[str, Any]] = {}
    cand_pw: list[str] = []
    for i, item in enumerate(data.get("credential_patterns") or []):
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("pattern"), str):
            errors.append(f"credential_patterns[{i}] 형식 오류")
            continue
        files = [str(f) for f in (item.get("files") or [])]
        try:
            rx = re.compile(item["pattern"], re.MULTILINE)
        except re.error as exc:
            errors.append(f"{item['id']}: 정규식 컴파일 실패: {exc}")
            rx = None
        cands = [str(c) for c in (item.get("candidate_passwords") or []) if c is not None]
        cand_pw.extend(cands)
        cp = CredentialPattern(
            id=str(item["id"]), files=files, pattern=item["pattern"], category=str(item.get("category") or "hardcoded-credential"),
            severity=str(item.get("severity_hint") or "medium").lower(), rationale=str(item.get("rationale") or ""),
            references=[str(r) for r in (item.get("references") or [])], rx=rx, file_rx=[glob_to_regex(f) for f in files], candidate_passwords=cands,
        )
        cps.append(cp)
        if cp.id.startswith("known-hash"):
            m = _KNOWN_HASH_RE.match(cp.pattern)
            if m:
                lit = _unescape_regex_literal(m.group("hash"))
                if lit:
                    known[lit] = {"id": cp.id, "user": m.group("user"), "severity_hint": cp.severity, "rationale": cp.rationale, "references": cp.references}
    if "tlJwpbo6" not in known:
        for cp in cps:
            if "tlJwpbo6" in cp.pattern:
                known["tlJwpbo6"] = {"id": cp.id, "user": None, "severity_hint": cp.severity, "rationale": cp.rationale, "references": cp.references}
                break
    fhs: list[dict[str, Any]] = []
    for i, item in enumerate(data.get("function_heuristics") or []):
        if not isinstance(item, dict) or not item.get("id"):
            errors.append(f"function_heuristics[{i}] 형식 오류")
            continue
        fh = dict(item)
        for key, dest in (("wrapper_name_regex", "_wrapper_rx"), ("format_regex", "_format_rx")):
            if isinstance(item.get(key), str):
                try:
                    fh[dest] = re.compile(item[key])
                except re.error as exc:
                    errors.append(f"{item['id']}.{key}: 컴파일 실패: {exc}")
        fhs.append(fh)
    wsb: dict[str, list[str]] = {}
    for vendor, names in (data.get("web_server_binaries") or {}).items():
        if isinstance(names, list):
            wsb[str(vendor)] = [str(n) for n in names]
    ip = [str(x) for x in (data.get("interesting_paths") or [])]
    ip_rx = []
    for g in ip:
        try:
            ip_rx.append((g, glob_to_regex(g)))
        except re.error as exc:
            errors.append(f"interesting_paths {g!r}: {exc}")
    seen_pw: set[str] = set()
    cand_unique = [c for c in cand_pw if not (c in seen_pw or seen_pw.add(c))]  # type: ignore[func-returns-value]
    if errors:
        log.warning("패턴 파일 경고 %d건: %s", len(errors), "; ".join(errors[:5]))
    return PatternSet(
        source=str(p), sha256=hashlib.sha256(raw_bytes).hexdigest(), version=data.get("version"),
        string_heuristics=sh, credential_patterns=cps, function_heuristics=fhs, web_server_binaries=wsb,
        interesting_paths=ip, interesting_rx=ip_rx, notes=[str(n) for n in (data.get("notes") or [])], errors=errors,
        known_hashes=known, candidate_passwords=cand_unique, pack=pack,
    )


def load_default_passwords() -> tuple[list[str], str]:
    """src/pweh/data/default-passwords.txt (주석 '#', 한 줄에 하나). (목록, 경로)."""
    import pweh.data as _data

    p = Path(_data.__file__).resolve().parent / "default-passwords.txt"
    words: list[str] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            w = line.rstrip("\r\n")
            if w and w not in words:
                words.append(w)
    except OSError:
        pass
    return words, str(p)
