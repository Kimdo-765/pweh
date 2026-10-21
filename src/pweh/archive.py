"""논리 증거 TAR/ZIP 의 한도 있는 목록·스트리밍 읽기. 호스트 경로로 추출하지 않는다.

비압축 TAR(ustar/GNU 긴 이름/PAX)와 단일 디스크 ZIP(stored/deflate/ZIP64)을 지원한다.
링크·특수 파일·sparse·암호화·다른 압축은 목록에만 남기고 내용을 읽지 않는다.
모든 바이트는 검증된 fd 에서 pread 로 읽으며 디렉터리·확장 헤더도 읽기 전에 크기를 제한한다.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import stat
import struct
import tarfile
import time
import zlib
from typing import Any, Callable, Iterator

from .fs import FsError

MAX_ENTRIES = 200_000
MAX_METADATA = 32 << 20
MAX_EXTRA = 1 << 20
MAX_NAME = 65536
BLOCK = 65536


def checkpoint(deadline: float, cancel: Callable[[], bool]) -> None:
    if cancel():
        raise FsError("아카이브 작업이 취소되었습니다.", reason="cancelled")
    if time.monotonic() >= deadline:
        raise FsError("아카이브 작업 시간 상한입니다.", reason="time")


def kind(fd: int) -> str | None:
    """최대 512 바이트로 컨테이너를 식별한다. 압축 TAR 후보는 해제하지 않는다."""
    b = os.pread(fd, 512, 0)
    if b[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x06\x06", b"PK\x07\x08"):
        return "zip"
    if b.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")):
        return "compressed-archive"
    if len(b) == 512:
        try:
            tarfile.TarInfo.frombuf(b, "utf-8", "surrogateescape")
            return "tar"
        except tarfile.HeaderError:
            if b[257:262] == b"ustar":
                return "tar"
    return None


def safe_member_path(name: str) -> bool:
    """아카이브의 원래 이름은 표시만 하고, 위험한 경로는 내용 선택에서도 거부한다."""
    return bool(name) and len(name) <= MAX_NAME and not (name.startswith(("/", "\\")) or "\x00" in name or "\\" in name
                  or re.match(r"^[A-Za-z]:", name) or any(p == ".." for p in name.split("/")))


def _epoch(raw: Any, source: str) -> dict[str, Any]:
    out = {"raw": raw, "iso": None, "valid": False, "time_basis": "utc", "source": source, "precision": "seconds"}
    try:
        value = float(raw)
        value_dt = dt.datetime.fromtimestamp(value, dt.timezone.utc)
        out.update(iso=value_dt.isoformat().replace("+00:00", "Z"), utc=value_dt.isoformat().replace("+00:00", "Z"), valid=True)
    except (ValueError, OverflowError, OSError, TypeError):
        pass
    return out


def _dos(date: int, clock: int) -> dict[str, Any]:
    out = {"raw": {"date": date, "time": clock}, "iso": None, "valid": False,
           "time_basis": "local-unknown-tz", "source": "zip-dos", "precision": "2-seconds"}
    try:
        out.update(iso=dt.datetime((date >> 9) + 1980, (date >> 5) & 15, date & 31,
                                  clock >> 11, (clock >> 5) & 63, (clock & 31) * 2).isoformat(), valid=True)
    except ValueError:
        pass
    return out


class Archive:
    """일반 파일 fd 를 빌려 쓰는 컨테이너. 목록에 포함된 항목만 읽을 수 있다."""

    def __init__(self, fd: int, *, max_entries: int = MAX_ENTRIES, deadline: float, cancel: Callable[[], bool]):
        self.fd, self.size = fd, os.fstat(fd).st_size
        self.format = kind(fd)
        self.deadline, self.cancel = deadline, cancel
        self.max_entries = max(1, min(int(max_entries), MAX_ENTRIES))
        self.entries: list[dict[str, Any]] = []
        self.reasons: set[str] = set()
        self.warnings: list[str] = []
        self.metadata_bytes = 0
        if self.format is None:
            raise FsError("지원하는 아카이브가 아닙니다.", reason="unsupported_archive")
        try:
            if self.format == "zip":
                self._zip()
            elif self.format == "tar":
                self._tar()
            else:
                self.reasons.add("unsupported_archive_compression")
        except FsError as exc:
            self.reasons.add(exc.reason)
            self.warnings.append(exc.message)

    def check(self) -> None:
        checkpoint(self.deadline, self.cancel)

    def read(self, offset: int, length: int) -> bytes:
        self.check()
        if offset < 0 or length < 0 or offset + length > self.size:
            raise FsError("아카이브 범위가 원본 끝을 넘습니다.", reason="incomplete_archive")
        if length > MAX_EXTRA:
            raise FsError("아카이브 메타데이터 1개가 상한을 넘습니다.", reason="max_metadata")
        data = os.pread(self.fd, length, offset)
        if len(data) != length:
            raise FsError("아카이브를 끝까지 읽지 못했습니다.", reason="incomplete_archive")
        return data

    def add(self, name: str, size: int, *, is_dir: bool, member_type: str, offset: int, times: dict[str, Any], **extra: Any) -> None:
        self.check()
        if len(self.entries) >= self.max_entries:
            raise FsError("아카이브 항목 수 상한입니다.", reason="max_entries")
        self.metadata_bytes += len(name.encode("utf-8", "surrogatepass")) + 512
        if self.metadata_bytes > MAX_METADATA or len(name) > MAX_NAME:
            raise FsError("아카이브 이름·항목 메타데이터 상한입니다.", reason="max_metadata")
        # surrogate 문자는 JSON/전송에 그대로 넘기지 않는다. ref 는 원래 순번이므로 선택은 모호하지 않다.
        name = name.encode("utf-8", "replace").decode("utf-8")
        safe = safe_member_path(name)
        blocked = None if safe else "unsafe_path"
        if member_type not in ("file", "directory"):
            blocked = "unsupported_member_type"
        e = {"ref": f"arc:{len(self.entries)}", "display_path": name, "display_name": name.rstrip("/").rsplit("/", 1)[-1],
             "size": size, "is_dir": is_dir, "deleted": False, "times": times, "member_type": member_type,
             "offset": offset, "sha256": None, "status": "unverified", "blocked_reason": blocked, **extra}
        self.entries.append(e)

    def _zip(self) -> None:
        tail_off = max(0, self.size - 65557)
        tail = self.read(tail_off, self.size - tail_off)
        pos = tail.rfind(b"PK\x05\x06")
        if pos < 0 or len(tail) - pos < 22:
            raise FsError("ZIP 종료 레코드가 없습니다.", reason="incomplete_archive")
        _, disk, cd_disk, disk_n, count, cd_size, cd_off, comment = struct.unpack_from("<4s4H2IH", tail, pos)
        end = tail_off + pos
        if pos + 22 + comment != len(tail) or disk or cd_disk or disk_n != count:
            raise FsError("분할 또는 잘못된 ZIP 종료 레코드입니다.", reason="unsupported_archive")
        if count == 65535 or cd_size == 0xffffffff or cd_off == 0xffffffff:
            loc = self.read(end - 20, 20)
            sig, disk64, off64, disks = struct.unpack("<4sIQI", loc)
            if sig != b"PK\x06\x07" or disk64 or disks != 1:
                raise FsError("ZIP64 locator 가 단일 디스크 형식이 아닙니다.", reason="unsupported_archive")
            rec = self.read(off64, 56)
            sig, reclen, made, need, disk, cd_disk, disk_n, count, cd_size, cd_off = struct.unpack("<4sQ2H2I4Q", rec)
            if sig != b"PK\x06\x06" or reclen < 44 or reclen > MAX_EXTRA or off64 + 12 + reclen != end - 20 or disk or cd_disk or disk_n != count:
                raise FsError("ZIP64 종료 레코드가 잘못되었습니다.", reason="invalid_archive")
            end = off64
        if cd_size > MAX_METADATA or count > MAX_ENTRIES:
            raise FsError("ZIP 중앙 디렉터리 크기·항목 수 상한입니다.", reason="max_metadata")
        if cd_off + cd_size != end or cd_off < 0 or count * 46 > cd_size:
            raise FsError("ZIP 중앙 디렉터리 범위가 잘못되었습니다.", reason="invalid_archive")
        at = cd_off
        for _ in range(count):
            head = self.read(at, 46)
            if head[:4] != b"PK\x01\x02":
                raise FsError("ZIP 중앙 디렉터리 헤더가 잘못되었습니다.", reason="invalid_archive")
            values = struct.unpack("<4s6H3I5H2I", head)
            _, made, need, flags, method, clock, date, crc, compressed, size, nl, xl, cl, disk, ia, ea, local = values
            if at + 46 + nl + xl + cl > cd_off + cd_size:
                raise FsError("ZIP 중앙 디렉터리가 잘렸습니다.", reason="incomplete_archive")
            nb = self.read(at + 46, nl)
            ext = self.read(at + 46 + nl, xl)
            at += 46 + nl + xl + cl
            try:
                name = nb.decode("utf-8" if flags & 0x800 else "cp437")
            except UnicodeDecodeError:
                raise FsError("ZIP 파일 이름 인코딩이 잘못되었습니다.", reason="invalid_archive") from None
            times = {"modified": _dos(date, clock)}
            extras: dict[int, bytes] = {}
            x = 0
            while x < len(ext):
                if x + 4 > len(ext):
                    raise FsError("ZIP extra 헤더가 잘렸습니다.", reason="invalid_archive")
                tag, n = struct.unpack_from("<HH", ext, x)
                if x + 4 + n > len(ext) or tag in extras:
                    raise FsError("ZIP extra 길이·중복 태그가 잘못되었습니다.", reason="invalid_archive")
                extras[tag] = ext[x + 4:x + 4 + n]
                x += 4 + n
            z64 = extras.get(1, b"")
            vals = [size, compressed, local, disk]
            q = 0
            for j, sentinel in enumerate((0xffffffff, 0xffffffff, 0xffffffff, 65535)):
                if vals[j] == sentinel:
                    width = 4 if j == 3 else 8
                    if q + width > len(z64):
                        raise FsError("ZIP64 항목 값이 없습니다.", reason="invalid_archive")
                    vals[j] = int.from_bytes(z64[q:q + width], "little")
                    q += width
            size, compressed, local, disk = vals
            ut = extras.get(0x5455, b"")
            if len(ut) >= 5 and ut[0] & 1:
                times["modified_dos"] = times["modified"]
                times["modified"] = _epoch(int.from_bytes(ut[1:5], "little"), "zip-ut")
            mode = ea >> 16 if made >> 8 == 3 else 0
            mtype = "directory" if name.endswith("/") or stat.S_ISDIR(mode) else "file"
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                mtype = "special"
            lh = self.read(local, 30)
            if lh[:4] != b"PK\x03\x04":
                raise FsError("ZIP local 헤더가 없습니다.", reason="invalid_archive")
            lv = struct.unpack("<4s5H3I2H", lh)
            lnl, lxl = lv[-2:]
            offset = local + 30 + lnl + lxl
            if lv[2] != flags or lv[3] != method or self.read(local + 30, lnl) != nb or offset + compressed > cd_off:
                raise FsError("ZIP local/central 헤더 또는 내용 범위가 다릅니다.", reason="invalid_archive")
            blocked = "encrypted_member" if flags & (1 | 0x40 | 0x2000) else ("unsupported_compression" if method not in (0, 8) else None)
            if disk:
                blocked = "multipart_archive"
            self.add(name, size, is_dir=mtype == "directory", member_type=mtype, offset=offset, times=times,
                     compressed_size=compressed, compression=method, crc32=crc, format="zip")
            if blocked:
                self.entries[-1]["blocked_reason"] = blocked
        if at != cd_off + cd_size:
            raise FsError("ZIP 중앙 디렉터리 크기가 항목들과 다릅니다.", reason="invalid_archive")

    def _pax(self, blob: bytes) -> dict[str, str]:
        out = {}
        at = 0
        while at < len(blob):
            self.check()
            sep = blob.find(b" ", at, min(at + 24, len(blob)))
            if sep < 0 or not blob[at:sep].isdigit():
                raise FsError("PAX 레코드 길이가 잘못되었습니다.", reason="invalid_archive")
            n = int(blob[at:sep])
            if n <= sep - at + 2 or at + n > len(blob) or blob[at + n - 1] != 10:
                raise FsError("PAX 레코드가 잘렸습니다.", reason="invalid_archive")
            key, eq, val = blob[sep + 1:at + n - 1].partition(b"=")
            if not eq:
                raise FsError("PAX 키/값이 잘못되었습니다.", reason="invalid_archive")
            out[key.decode("utf-8", "replace")] = val.decode("utf-8", "replace")
            at += n
        return out

    def _tar(self) -> None:
        at, ext_bytes = 0, 0
        pending: dict[str, str] = {}
        global_pax: dict[str, str] = {}
        longname = None
        while at < self.size:
            header = self.read(at, 512)
            if header == b"\x00" * 512:
                if at + 1024 > self.size or self.read(at + 512, 512) != b"\x00" * 512:
                    raise FsError("TAR 종료 블록이 잘렸습니다.", reason="incomplete_archive")
                tail = at + 1024
                if self.size - tail > MAX_METADATA:
                    raise FsError("TAR 종료 뒤 패딩이 검사 상한을 넘습니다.", reason="trailing_data_unexamined")
                while tail < self.size:
                    n = min(BLOCK, self.size - tail)
                    if any(self.read(tail, n)):
                        raise FsError("TAR 종료 뒤에 해석하지 않은 데이터가 있습니다.", reason="trailing_data")
                    tail += n
                return
            try:
                ti = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            except tarfile.HeaderError:
                raise FsError("TAR 헤더 체크섬·형식이 잘못되었습니다.", reason="invalid_archive") from None
            offset = at + 512
            if ti.size < 0 or offset + ti.size > self.size:
                raise FsError("TAR 항목이 원본 끝을 넘습니다.", reason="incomplete_archive")
            if ti.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                if ti.size > MAX_EXTRA or ext_bytes + ti.size > MAX_METADATA:
                    raise FsError("TAR 확장 헤더가 상한을 넘습니다.", reason="max_metadata")
                blob = self.read(offset, ti.size)
                ext_bytes += ti.size
                if ti.type == tarfile.XHDTYPE:
                    pending.update(self._pax(blob))
                elif ti.type == tarfile.XGLTYPE:
                    global_pax.update(self._pax(blob))
                elif ti.type == tarfile.GNUTYPE_LONGNAME:
                    longname = blob.rstrip(b"\x00").decode("utf-8", "replace")
                at = offset + ((ti.size + 511) // 512) * 512
                continue
            pax = {**global_pax, **pending}
            name = pax.get("path", longname if longname is not None else ti.name)
            size = ti.size
            if "size" in pax:
                if not re.fullmatch(r"[0-9]{1,20}", pax["size"]):
                    raise FsError("PAX 파일 크기가 잘못되었습니다.", reason="invalid_archive")
                size = int(pax["size"])
            if offset + size > self.size:
                raise FsError("PAX 파일이 원본 끝을 넘습니다.", reason="incomplete_archive")
            mtype = "file" if ti.isfile() else ("directory" if ti.isdir() else "special")
            if ti.type == tarfile.GNUTYPE_SPARSE or any(k.startswith("GNU.sparse") for k in pax):
                # GNU sparse 확장 블록까지 따라가면 다음 항목 경계를 잘못 믿을 수 있다.
                raise FsError("TAR sparse 는 지원하지 않습니다.", reason="unsupported_sparse")
            times = {"modified": _epoch(pax.get("mtime", ti.mtime), "tar-pax" if "mtime" in pax else "tar")}
            for key, label in (("atime", "accessed"), ("ctime", "changed")):
                if key in pax:
                    times[label] = _epoch(pax[key], "tar-pax")
            self.add(name, size, is_dir=ti.isdir(), member_type=mtype, offset=offset, times=times,
                     compressed_size=size, compression=0, format="tar")
            pending, longname = {}, None
            at = offset + ((size + 511) // 512) * 512
        raise FsError("TAR 종료 블록이 없습니다.", reason="incomplete_archive")

    def select(self, ref: str | None, path: str | None) -> dict[str, Any]:
        self.check()
        if bool(ref) == bool(path):
            raise FsError("ref 또는 path 하나만 선택해야 합니다.", reason="bad_argument")
        found = [e for e in self.entries if (e["ref"] == ref if ref else e["display_path"] == path)]
        if not found and path:
            found = [e for e in self.entries if e["display_path"].removeprefix("./") == path.removeprefix("./")]
        if len(found) != 1:
            reason = "ambiguous_path" if len(found) > 1 else ("refs_unverifiable" if self.reasons else "not_found")
            raise FsError("아카이브 항목 1개를 확정하지 못했습니다.", reason=reason)
        if path and self.reasons:
            raise FsError("목록이 불완전하여 같은 이름이 더 있는지 확인하지 못했습니다(ref 사용).", reason="refs_unverifiable")
        e = found[0]
        if e["blocked_reason"] or e["is_dir"]:
            raise FsError("이 아카이브 항목은 내용 선택을 허용하지 않습니다.", reason=e["blocked_reason"] or "is_directory")
        return e

    def chunks(self, e: dict[str, Any], *, max_bytes: int) -> Iterator[bytes]:
        # 목록 멤버 검증은 O(1)이다. entries 전체 비교를 하면 작은 파일 수십만 개의 해시가 O(n²)이 된다.
        ref = e.get("ref", "")
        idx = int(ref[4:]) if isinstance(ref, str) and re.fullmatch(r"arc:[0-9]{1,6}", ref) else -1
        if not 0 <= idx < len(self.entries) or self.entries[idx] is not e or e.get("blocked_reason") or e.get("is_dir"):
            raise FsError("검증되지 않은 아카이브 항목입니다.", reason="bad_ref")
        if e["size"] > max_bytes:
            raise FsError("아카이브 멤버가 읽기 바이트 상한을 넘습니다.", reason="max_bytes")
        offset, left = e["offset"], e["compressed_size"]
        dec = zlib.decompressobj(-15) if e["compression"] == 8 else None
        total, crc = 0, 0
        try:
            while left:
                self.check()
                n = min(BLOCK, left)
                raw = self.read(offset, n)
                offset, left = offset + n, left - n
                pending = raw
                while pending:
                    self.check()
                    blob = dec.decompress(pending, BLOCK) if dec else pending
                    pending = dec.unconsumed_tail if dec else b""
                    total += len(blob)
                    if total > max_bytes or total > e["size"]:
                        raise FsError("아카이브 해제 바이트가 선언 크기·상한을 넘습니다.", reason="max_bytes")
                    crc = zlib.crc32(blob, crc)
                    if blob:
                        yield blob
                    if dec and dec.unused_data:
                        raise FsError("ZIP 압축 스트림 뒤에 불명확한 데이터가 있습니다.", reason="invalid_archive")
            if total != e["size"] or (dec and not dec.eof):
                raise FsError("아카이브 파일 내용이 불완전합니다.", reason="incomplete_file")
            if e["format"] == "zip" and crc != e["crc32"]:
                raise FsError("ZIP 멤버 CRC 가 다릅니다.", reason="crc_mismatch")
        except zlib.error:
            raise FsError("ZIP deflate 스트림이 손상되었습니다.", reason="invalid_archive") from None

    def inventory(self, *, hash_members: bool, max_hash_bytes: int) -> dict[str, Any]:
        spent = 0
        for e in self.entries:
            if e["is_dir"]:
                e["status"] = "directory"
                continue
            if e["blocked_reason"]:
                e["status"] = "unsupported"
                self.reasons.add(e["blocked_reason"])
                continue
            if not hash_members:
                continue
            if e["size"] > max_hash_bytes - spent:
                self.reasons.add("max_hash_bytes")
                continue
            h = hashlib.sha256()
            try:
                for blob in self.chunks(e, max_bytes=max_hash_bytes - spent):
                    h.update(blob)
                    spent += len(blob)
                e["sha256"], e["status"] = h.hexdigest(), "verified"
            except FsError as exc:
                self.reasons.add(exc.reason)
                e["error"] = exc.reason
                if exc.reason in ("time", "cancelled"):
                    break
                e["status"] = "failed"
        return {"format": self.format, "entries": self.entries, "truncated": bool(self.reasons),
                "truncated_reasons": sorted(self.reasons), "warnings": self.warnings, "bytes_hashed": spent,
                "hash_members": hash_members}
