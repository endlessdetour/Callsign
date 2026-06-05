import asyncio
import ctypes
import os
import sys
import uuid
from ctypes import wintypes
from pathlib import Path


WINTUN_MIN_RING_CAPACITY = 0x20000
WINTUN_DEFAULT_RING_CAPACITY = 0x400000
WAIT_OBJECT_0 = 0
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def guid_from_uuid(value: uuid.UUID) -> GUID:
    data = value.bytes_le
    return GUID(
        int.from_bytes(data[0:4], "little"),
        int.from_bytes(data[4:6], "little"),
        int.from_bytes(data[6:8], "little"),
        (ctypes.c_ubyte * 8).from_buffer_copy(data[8:16]),
    )


class WintunAdapter:
    def __init__(self, adapter_name: str = "CallsignTunnel", ring_capacity: int = WINTUN_DEFAULT_RING_CAPACITY):
        if os.name != "nt":
            raise RuntimeError("Wintun adapter is only available on Windows")

        self.adapter_name = adapter_name
        self.ring_capacity = max(WINTUN_MIN_RING_CAPACITY, ring_capacity)
        self._dll = ctypes.WinDLL(str(self._resolve_dll_path()), use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_api()

        self._adapter = None
        self._session = None

        self._open_or_create_adapter()
        self._start_session()

    def _resolve_dll_path(self) -> Path:
        env_path = os.getenv("WINTUN_DLL_PATH", "").strip()
        if env_path:
            candidate = Path(env_path)
            if candidate.exists():
                return candidate

        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).resolve().parent
            bundled = exe_dir / "wintun.dll"
            if bundled.exists():
                return bundled

            # PyInstaller onedir commonly stores collected binaries in _internal.
            bundled_internal = exe_dir / "_internal" / "wintun.dll"
            if bundled_internal.exists():
                return bundled_internal

            meipass = getattr(sys, "_MEIPASS", "")
            if meipass:
                bundled_meipass = Path(meipass) / "wintun.dll"
                if bundled_meipass.exists():
                    return bundled_meipass

        base = Path(__file__).resolve().parents[2] / "third_party" / "wintun"
        machine = os.environ.get("PROCESSOR_ARCHITECTURE", "").lower()
        if "arm64" in machine:
            preferred = base / "wintun" / "bin" / "arm64" / "wintun.dll"
        elif "amd64" in machine or "x86_64" in machine:
            preferred = base / "wintun" / "bin" / "amd64" / "wintun.dll"
        else:
            preferred = base / "wintun" / "bin" / "x86" / "wintun.dll"
        if preferred.exists():
            return preferred

        for candidate in base.glob("**/wintun.dll"):
            if candidate.exists():
                return candidate

        raise RuntimeError(
            "wintun.dll not found. Put it next to executable or set WINTUN_DLL_PATH. "
            "Download signed binary from https://www.wintun.net/."
        )

    def _configure_api(self):
        self._dll.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        self._dll.WintunOpenAdapter.restype = ctypes.c_void_p

        self._dll.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(GUID)]
        self._dll.WintunCreateAdapter.restype = ctypes.c_void_p

        self._dll.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        self._dll.WintunCloseAdapter.restype = None

        self._dll.WintunStartSession.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self._dll.WintunStartSession.restype = ctypes.c_void_p

        self._dll.WintunEndSession.argtypes = [ctypes.c_void_p]
        self._dll.WintunEndSession.restype = None

        self._dll.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        self._dll.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        self._dll.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        self._dll.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        self._dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        self._dll.WintunReleaseReceivePacket.restype = None

        self._dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self._dll.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        self._dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        self._dll.WintunSendPacket.restype = None

        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD

    def _open_or_create_adapter(self):
        adapter = self._dll.WintunOpenAdapter(self.adapter_name)
        if adapter:
            self._adapter = adapter
            return

        requested_guid = guid_from_uuid(uuid.uuid5(uuid.NAMESPACE_DNS, f"callsign:{self.adapter_name}"))
        adapter = self._dll.WintunCreateAdapter(self.adapter_name, "Callsign", ctypes.byref(requested_guid))
        if not adapter:
            err = ctypes.get_last_error()
            raise RuntimeError(f"failed to create Wintun adapter (WinError {err})")
        self._adapter = adapter

    def _start_session(self):
        session = self._dll.WintunStartSession(self._adapter, self.ring_capacity)
        if not session:
            err = ctypes.get_last_error()
            raise RuntimeError(f"failed to start Wintun session (WinError {err})")
        self._session = session

    def close(self):
        if self._session:
            self._dll.WintunEndSession(self._session)
            self._session = None
        if self._adapter:
            self._dll.WintunCloseAdapter(self._adapter)
            self._adapter = None

    def _read_packet_sync(self) -> bytes:
        if not self._session:
            raise RuntimeError("Wintun session closed")

        packet_size = wintypes.DWORD()
        while True:
            packet_ptr = self._dll.WintunReceivePacket(self._session, ctypes.byref(packet_size))
            if packet_ptr:
                try:
                    return bytes(ctypes.string_at(packet_ptr, packet_size.value))
                finally:
                    self._dll.WintunReleaseReceivePacket(self._session, packet_ptr)

            wait_event = self._dll.WintunGetReadWaitEvent(self._session)
            if not wait_event:
                raise RuntimeError("failed to get Wintun read event")

            wait_result = self._kernel32.WaitForSingleObject(wait_event, INFINITE)
            if wait_result == WAIT_OBJECT_0:
                continue
            if wait_result == WAIT_FAILED:
                raise RuntimeError("Wintun read wait failed")

    async def read_packet(self) -> bytes:
        return await asyncio.to_thread(self._read_packet_sync)

    async def write_packet(self, data: bytes) -> None:
        if not self._session:
            raise RuntimeError("Wintun session closed")
        if not data:
            return

        packet = self._dll.WintunAllocateSendPacket(self._session, len(data))
        if not packet:
            raise RuntimeError("failed allocating Wintun send packet")

        ctypes.memmove(packet, data, len(data))
        self._dll.WintunSendPacket(self._session, packet)
