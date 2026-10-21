"""고정 component 두 개만 내려받는 격리 container 진입점. 앱/CMake를 실행하지 않는다."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import subprocess
import time
import urllib.parse
import urllib.request


def run(argv):
    """출력/시간이 제한된 준비 전용 하위 명령."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + 850
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise ValueError("component 준비 시간 초과")
            for key, _ in selector.select(.2):
                part = os.read(key.fd, 65536)
                if not part:
                    selector.unregister(key.fileobj)
                data.extend(part)
                if len(data) > 8 * 1024 * 1024:
                    raise ValueError("component 준비 출력 상한 초과")
        if proc.wait(timeout=5):
            raise ValueError(data[-2000:].decode("utf-8", "replace"))
        return bytes(data)
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


class FixedRedirect(urllib.request.HTTPRedirectHandler):
    """승인된 공식 storage host 밖 redirect를 따라가지 않는다."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def check_url(url):
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or parts.netloc != "components-file.espressif.com" or parts.query or parts.fragment
            or not parts.path.startswith("/components/espressif/") or ".." in parts.path.split("/")):
        raise ValueError("고정 component storage URL 밖 요청 거부")


resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
version = importlib.metadata.version("idf-component-manager")
source = Path("/work/mirror")
source.mkdir()
lock = json.loads(Path("/input/components-lock.json").read_text())
if {row["name"]: row["version"] for row in lock["components"]} != {"espressif/esp_tinyusb": "2.4.0", "espressif/tinyusb": "0.21.0~2"}:
    raise ValueError("component exact pin 불일치")
opener = urllib.request.build_opener(FixedRedirect())
for component in lock["components"]:
    for entry in component["files"]:
        check_url(entry["url"])
        if not 0 < entry["size"] <= 64 * 1024 * 1024:
            raise ValueError("component download 크기 상한")
        with opener.open(entry["url"], timeout=30) as response:
            blob = response.read(entry["size"] + 1)
        if len(blob) != entry["size"] or hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise ValueError("component 원본 archive/checksums SHA256 불일치")
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("component 상대 경로 오류")
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    metadata = source / "components" / (component["name"] + ".json")
    metadata.write_text(json.dumps(component["metadata"], sort_keys=True) + "\n")
result = "고정 archive 2개와 CHECKSUMS 2개 SHA256 검증 완료\n".encode()
output = Path("/out/mirror")
rows = []
total = 0
for path in sorted(source.rglob("*")):
    if path.is_symlink() or not (path.is_dir() or path.is_file()):
        raise ValueError("component mirror link/특수 파일 거부")
    if path.is_dir():
        continue
    rel = path.relative_to(source).as_posix()
    total += path.stat().st_size
    if len(rel) > 256 or len(rows) >= 20000 or total > 256 * 1024 * 1024:
        raise ValueError("component mirror 파일/크기 상한 초과")
    blob = path.read_bytes()
    rows.append({"path": rel, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
for row in rows:
    dest = output / row["path"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / row["path"], dest)
Path("/out/component-download.log").write_bytes(result)
Path("/out/mirror-files.json").write_text(json.dumps({"manager_version": version, "files": rows}, indent=2) + "\n")
