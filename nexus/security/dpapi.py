from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


class DpapiError(RuntimeError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def protect(data: bytes, entropy: bytes = b"NEXUS-Quarantine-v1") -> bytes:
    if os.name != "nt":
        raise DpapiError("DPAPI solo esta disponible en Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    data_in, data_in_buffer = _blob(data)
    entropy_in, entropy_buffer = _blob(entropy)
    data_out = DATA_BLOB()
    result = crypt32.CryptProtectData(
        ctypes.byref(data_in),
        ctypes.c_wchar_p("NEXUS Quarantine Key"),
        ctypes.byref(entropy_in),
        None,
        None,
        0x1,
        ctypes.byref(data_out),
    )
    if not result:
        raise DpapiError(f"CryptProtectData fallo: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(data_out.pbData)
        del data_in_buffer, entropy_buffer


def unprotect(data: bytes, entropy: bytes = b"NEXUS-Quarantine-v1") -> bytes:
    if os.name != "nt":
        raise DpapiError("DPAPI solo esta disponible en Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    data_in, data_in_buffer = _blob(data)
    entropy_in, entropy_buffer = _blob(entropy)
    data_out = DATA_BLOB()
    result = crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy_in),
        None,
        None,
        0x1,
        ctypes.byref(data_out),
    )
    if not result:
        raise DpapiError(f"CryptUnprotectData fallo: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(data_out.pbData)
        del data_in_buffer, entropy_buffer
