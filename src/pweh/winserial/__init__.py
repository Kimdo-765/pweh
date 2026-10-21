"""핀으로 고정한 Windows 직렬 helper. import만으로 환경/파일/기기를 조회하지 않는다."""

__all__ = ["HelperSerial", "HelperBinary", "resolve_helper"]


def __getattr__(name):
    if name == "HelperSerial":
        from .serial import HelperSerial
        return HelperSerial
    if name in ("HelperBinary", "resolve_helper"):
        from . import binary
        return getattr(binary, name)
    raise AttributeError(name)
