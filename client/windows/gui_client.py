import json
import os
import base64
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import ctypes
import ctypes.wintypes
import tkinter as tk
import traceback
from tkinter import messagebox, simpledialog, ttk

_DPAPI_PREFIX = "DPAPI:"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_protect(plaintext: str) -> str:
    """Encrypt a string with Windows DPAPI (per-user). Returns base64 or '' on failure."""
    if os.name != "nt" or not plaintext:
        return ""
    try:
        data = plaintext.encode("utf-8")
        buf_in = ctypes.create_string_buffer(data, len(data))
        blob_in = _DATA_BLOB(len(data), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            return ""
        try:
            raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return base64.b64encode(raw).decode("ascii")
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return ""


def _dpapi_unprotect(b64: str) -> str:
    """Decrypt a base64 DPAPI blob back to a string. Returns '' on failure."""
    if os.name != "nt" or not b64:
        return ""
    try:
        raw = base64.b64decode(b64.encode("ascii"))
        buf_in = ctypes.create_string_buffer(raw, len(raw))
        blob_in = _DATA_BLOB(len(raw), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            return ""
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    except Exception:
        return ""


_single_instance_mutex = None
_single_instance_lock_file = None


if os.name == "nt":
    class _WndClassEx(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.UINT),
            ("style", ctypes.wintypes.UINT),
            ("lpfnWndProc", ctypes.c_void_p),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", ctypes.wintypes.HINSTANCE),
            ("hIcon", ctypes.wintypes.HICON),
            ("hCursor", ctypes.wintypes.HCURSOR),
            ("hbrBackground", ctypes.wintypes.HBRUSH),
            ("lpszMenuName", ctypes.wintypes.LPCWSTR),
            ("lpszClassName", ctypes.wintypes.LPCWSTR),
            ("hIconSm", ctypes.wintypes.HICON),
        ]


    class _NotifyIconData(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.DWORD),
            ("hWnd", ctypes.wintypes.HWND),
            ("uID", ctypes.wintypes.UINT),
            ("uFlags", ctypes.wintypes.UINT),
            ("uCallbackMessage", ctypes.wintypes.UINT),
            ("hIcon", ctypes.wintypes.HICON),
            ("szTip", ctypes.wintypes.WCHAR * 128),
            ("dwState", ctypes.wintypes.DWORD),
            ("dwStateMask", ctypes.wintypes.DWORD),
            ("szInfo", ctypes.wintypes.WCHAR * 256),
            ("uTimeoutOrVersion", ctypes.wintypes.UINT),
            ("szInfoTitle", ctypes.wintypes.WCHAR * 64),
            ("dwInfoFlags", ctypes.wintypes.DWORD),
            ("guidItem", ctypes.c_byte * 16),
            ("hBalloonIcon", ctypes.wintypes.HICON),
        ]


    class WindowsTrayIcon:
        WM_USER = 0x0400
        WM_APP = 0x8000
        WM_TRAYICON = WM_USER + 20
        WM_TRAY_REFRESH = WM_APP + 21
        WM_CLOSE = 0x0010
        WM_DESTROY = 0x0002
        WM_RBUTTONUP = 0x0205
        WM_LBUTTONDBLCLK = 0x0203

        NIM_ADD = 0x00000000
        NIM_MODIFY = 0x00000001
        NIM_DELETE = 0x00000002

        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004

        MF_STRING = 0x00000000
        TPM_RETURNCMD = 0x0100
        TPM_LEFTALIGN = 0x0000

        MENU_ID_TOGGLE = 1001
        MENU_ID_SHOW = 1002
        MENU_ID_EXIT = 1003

        def __init__(self, on_show, on_toggle_connection, on_exit, is_connected, get_tooltip):
            self._on_show = on_show
            self._on_toggle_connection = on_toggle_connection
            self._on_exit = on_exit
            self._is_connected = is_connected
            self._get_tooltip = get_tooltip

            self._thread = None
            self._hwnd = None
            self._hinstance = ctypes.windll.kernel32.GetModuleHandleW(None)
            self._class_name = "CallsignTrayWindow"
            self._notify_id = 1
            self._wndproc_ref = None
            self._icon_connected = None
            self._icon_disconnected = None

        def start(self):
            if self._thread is not None:
                return
            self._ensure_icons()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

        def stop(self):
            if self._hwnd:
                ctypes.windll.user32.PostMessageW(self._hwnd, self.WM_CLOSE, 0, 0)
            if self._thread is not None:
                self._thread.join(timeout=2)
            self._thread = None
            self._hwnd = None
            self._destroy_icons()

        def update(self):
            if self._hwnd:
                ctypes.windll.user32.PostMessageW(self._hwnd, self.WM_TRAY_REFRESH, 0, 0)

        def _notify_icon(self, action: int):
            if not self._hwnd:
                return
            self._ensure_icons()
            nid = _NotifyIconData()
            nid.cbSize = ctypes.sizeof(_NotifyIconData)
            nid.hWnd = self._hwnd
            nid.uID = self._notify_id
            nid.uFlags = self.NIF_ICON | self.NIF_MESSAGE | self.NIF_TIP
            nid.uCallbackMessage = self.WM_TRAYICON
            nid.hIcon = self._icon_connected if self._is_connected() else self._icon_disconnected
            nid.szTip = self._get_tooltip()[:127]
            ctypes.windll.shell32.Shell_NotifyIconW(action, ctypes.byref(nid))

        def _ensure_icons(self):
            if self._icon_connected is not None and self._icon_disconnected is not None:
                return

            custom_icon = self._load_custom_icon(16)
            if custom_icon is not None:
                self._icon_disconnected = custom_icon
                badged_icon = self._build_badged_icon(custom_icon, 16, 16)
                self._icon_connected = badged_icon if badged_icon is not None else self._build_icon(connected=True)
                return

            self._icon_connected = self._build_icon(connected=True)
            self._icon_disconnected = self._build_icon(connected=False)

        def _load_custom_icon(self, size: int):
            exe_icon = self._load_icon_from_executable(size)
            if exe_icon is not None:
                return exe_icon

            icon_path = self._resolve_icon_path()
            if icon_path is None:
                return None

            IMAGE_ICON = 1
            LR_LOADFROMFILE = 0x0010
            handle = ctypes.windll.user32.LoadImageW(
                None,
                icon_path,
                IMAGE_ICON,
                size,
                size,
                LR_LOADFROMFILE,
            )
            return handle or None

        def _load_icon_from_executable(self, size: int):
            if not getattr(sys, "frozen", False):
                return None

            large = ctypes.wintypes.HICON()
            small = ctypes.wintypes.HICON()
            extracted = ctypes.windll.shell32.ExtractIconExW(
                str(Path(sys.executable).resolve()),
                0,
                ctypes.byref(large),
                ctypes.byref(small),
                1,
            )
            if extracted <= 0:
                return None

            base = small.value or large.value
            if not base:
                return None

            copied = ctypes.windll.user32.CopyImage(
                base,
                1,
                size,
                size,
                0,
            )
            if large.value:
                ctypes.windll.user32.DestroyIcon(large.value)
            if small.value:
                ctypes.windll.user32.DestroyIcon(small.value)
            return copied or base

        def _resolve_icon_path(self):
            candidates = []
            if getattr(sys, "frozen", False):
                exe_dir = Path(sys.executable).resolve().parent
                candidates.extend([
                    exe_dir / "assets" / "callsign.ico",
                    exe_dir / "_internal" / "assets" / "callsign.ico",
                    exe_dir / "callsign.ico",
                ])
            else:
                repo_root = Path(__file__).resolve().parents[2]
                candidates.append(repo_root / "assets" / "callsign.ico")

            for candidate in candidates:
                if candidate.exists():
                    return str(candidate)
            return None

        def _build_badged_icon(self, hicon, width: int, height: int):
            pixels = self._extract_icon_pixels(hicon, width, height)
            if pixels is None:
                return None

            def set_px(x: int, y: int, r: int, g: int, b: int, a: int = 255):
                if not (0 <= x < width and 0 <= y < height):
                    return
                idx = (y * width + x) * 4
                pixels[idx] = b
                pixels[idx + 1] = g
                pixels[idx + 2] = r
                pixels[idx + 3] = a

            cx, cy, radius = width - 4, height - 4, 4
            for y in range(cy - radius, cy + radius + 1):
                for x in range(cx - radius, cx + radius + 1):
                    dx, dy = x - cx, y - cy
                    if dx * dx + dy * dy <= radius * radius:
                        set_px(x, y, 42, 200, 95)

            # White check mark over badge.
            check_points = [
                (cx - 2, cy),
                (cx - 1, cy + 1),
                (cx, cy + 2),
                (cx + 1, cy + 1),
                (cx + 2, cy),
                (cx + 3, cy - 1),
            ]
            for x, y in check_points:
                set_px(x, y, 255, 255, 255)
                set_px(x, y - 1, 255, 255, 255)

            return self._create_icon_from_pixels(pixels, width, height)

        def _extract_icon_pixels(self, hicon, width: int, height: int):
            class _BitmapInfoHeader(ctypes.Structure):
                _fields_ = [
                    ("biSize", ctypes.wintypes.DWORD),
                    ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long),
                    ("biPlanes", ctypes.wintypes.WORD),
                    ("biBitCount", ctypes.wintypes.WORD),
                    ("biCompression", ctypes.wintypes.DWORD),
                    ("biSizeImage", ctypes.wintypes.DWORD),
                    ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long),
                    ("biClrUsed", ctypes.wintypes.DWORD),
                    ("biClrImportant", ctypes.wintypes.DWORD),
                ]

            class _BitmapInfo(ctypes.Structure):
                _fields_ = [("bmiHeader", _BitmapInfoHeader), ("bmiColors", ctypes.wintypes.DWORD * 3)]

            user32 = ctypes.windll.user32
            gdi32 = ctypes.windll.gdi32
            DI_NORMAL = 0x0003

            bmi = _BitmapInfo()
            bmi.bmiHeader.biSize = ctypes.sizeof(_BitmapInfoHeader)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0

            screen_dc = user32.GetDC(None)
            bits = ctypes.c_void_p()
            hbm = gdi32.CreateDIBSection(screen_dc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
            if not hbm or not bits:
                user32.ReleaseDC(None, screen_dc)
                return None

            mem_dc = gdi32.CreateCompatibleDC(screen_dc)
            old_obj = gdi32.SelectObject(mem_dc, hbm)
            ctypes.memset(bits, 0, width * height * 4)
            user32.DrawIconEx(mem_dc, 0, 0, hicon, width, height, 0, None, DI_NORMAL)
            raw = ctypes.string_at(bits, width * height * 4)

            gdi32.SelectObject(mem_dc, old_obj)
            gdi32.DeleteDC(mem_dc)
            gdi32.DeleteObject(hbm)
            user32.ReleaseDC(None, screen_dc)
            return bytearray(raw)

        def _create_icon_from_pixels(self, pixels: bytearray, width: int, height: int):
            class _BitmapInfoHeader(ctypes.Structure):
                _fields_ = [
                    ("biSize", ctypes.wintypes.DWORD),
                    ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long),
                    ("biPlanes", ctypes.wintypes.WORD),
                    ("biBitCount", ctypes.wintypes.WORD),
                    ("biCompression", ctypes.wintypes.DWORD),
                    ("biSizeImage", ctypes.wintypes.DWORD),
                    ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long),
                    ("biClrUsed", ctypes.wintypes.DWORD),
                    ("biClrImportant", ctypes.wintypes.DWORD),
                ]

            class _BitmapInfo(ctypes.Structure):
                _fields_ = [("bmiHeader", _BitmapInfoHeader), ("bmiColors", ctypes.wintypes.DWORD * 3)]

            class _IconInfo(ctypes.Structure):
                _fields_ = [
                    ("fIcon", ctypes.wintypes.BOOL),
                    ("xHotspot", ctypes.wintypes.DWORD),
                    ("yHotspot", ctypes.wintypes.DWORD),
                    ("hbmMask", ctypes.wintypes.HBITMAP),
                    ("hbmColor", ctypes.wintypes.HBITMAP),
                ]

            user32 = ctypes.windll.user32
            gdi32 = ctypes.windll.gdi32

            bmi = _BitmapInfo()
            bmi.bmiHeader.biSize = ctypes.sizeof(_BitmapInfoHeader)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0

            hdc = user32.GetDC(None)
            bits = ctypes.c_void_p()
            hbm_color = gdi32.CreateDIBSection(hdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
            user32.ReleaseDC(None, hdc)
            if not hbm_color or not bits:
                return None

            buffer = (ctypes.c_ubyte * len(pixels)).from_buffer(pixels)
            ctypes.memmove(bits, buffer, len(pixels))

            hbm_mask = gdi32.CreateBitmap(width, height, 1, 1, None)
            icon_info = _IconInfo()
            icon_info.fIcon = True
            icon_info.xHotspot = 0
            icon_info.yHotspot = 0
            icon_info.hbmMask = hbm_mask
            icon_info.hbmColor = hbm_color

            hicon = user32.CreateIconIndirect(ctypes.byref(icon_info))
            gdi32.DeleteObject(hbm_color)
            gdi32.DeleteObject(hbm_mask)
            return hicon or None

        def _destroy_icons(self):
            if self._icon_connected is not None:
                ctypes.windll.user32.DestroyIcon(self._icon_connected)
                self._icon_connected = None
            if self._icon_disconnected is not None:
                ctypes.windll.user32.DestroyIcon(self._icon_disconnected)
                self._icon_disconnected = None

        def _build_icon(self, connected: bool):
            width, height = 16, 16
            pixels = bytearray(width * height * 4)

            def set_px(x: int, y: int, r: int, g: int, b: int, a: int = 255):
                if not (0 <= x < width and 0 <= y < height):
                    return
                idx = (y * width + x) * 4
                pixels[idx] = b
                pixels[idx + 1] = g
                pixels[idx + 2] = r
                pixels[idx + 3] = a

            # Base shield-like tile.
            base_r, base_g, base_b = (63, 77, 96)
            border_r, border_g, border_b = (36, 45, 60)
            for y in range(height):
                for x in range(width):
                    is_border = x in (0, width - 1) or y in (0, height - 1)
                    if is_border:
                        set_px(x, y, border_r, border_g, border_b)
                    else:
                        set_px(x, y, base_r, base_g, base_b)

            if connected:
                # Green check for connected state.
                for i in range(4):
                    set_px(4 + i, 9 + i, 42, 200, 95)
                    set_px(4 + i, 8 + i, 42, 200, 95)
                for i in range(6):
                    set_px(7 + i, 12 - i, 42, 200, 95)
                    set_px(7 + i, 11 - i, 42, 200, 95)
            else:
                # Gray minus for disconnected state.
                for x in range(4, 12):
                    set_px(x, 8, 180, 188, 202)
                    set_px(x, 9, 180, 188, 202)

            class _BitmapInfoHeader(ctypes.Structure):
                _fields_ = [
                    ("biSize", ctypes.wintypes.DWORD),
                    ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long),
                    ("biPlanes", ctypes.wintypes.WORD),
                    ("biBitCount", ctypes.wintypes.WORD),
                    ("biCompression", ctypes.wintypes.DWORD),
                    ("biSizeImage", ctypes.wintypes.DWORD),
                    ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long),
                    ("biClrUsed", ctypes.wintypes.DWORD),
                    ("biClrImportant", ctypes.wintypes.DWORD),
                ]

            class _BitmapInfo(ctypes.Structure):
                _fields_ = [("bmiHeader", _BitmapInfoHeader), ("bmiColors", ctypes.wintypes.DWORD * 3)]

            class _IconInfo(ctypes.Structure):
                _fields_ = [
                    ("fIcon", ctypes.wintypes.BOOL),
                    ("xHotspot", ctypes.wintypes.DWORD),
                    ("yHotspot", ctypes.wintypes.DWORD),
                    ("hbmMask", ctypes.wintypes.HBITMAP),
                    ("hbmColor", ctypes.wintypes.HBITMAP),
                ]

            bmi = _BitmapInfo()
            bmi.bmiHeader.biSize = ctypes.sizeof(_BitmapInfoHeader)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0

            user32 = ctypes.windll.user32
            gdi32 = ctypes.windll.gdi32

            hdc = user32.GetDC(None)
            bits = ctypes.c_void_p()
            hbm_color = gdi32.CreateDIBSection(hdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
            user32.ReleaseDC(None, hdc)
            if not hbm_color or not bits:
                return user32.LoadIconW(None, ctypes.wintypes.LPCWSTR(32512))

            buffer = (ctypes.c_ubyte * len(pixels)).from_buffer(pixels)
            ctypes.memmove(bits, buffer, len(pixels))

            hbm_mask = gdi32.CreateBitmap(width, height, 1, 1, None)
            icon_info = _IconInfo()
            icon_info.fIcon = True
            icon_info.xHotspot = 0
            icon_info.yHotspot = 0
            icon_info.hbmMask = hbm_mask
            icon_info.hbmColor = hbm_color

            hicon = user32.CreateIconIndirect(ctypes.byref(icon_info))
            gdi32.DeleteObject(hbm_color)
            gdi32.DeleteObject(hbm_mask)
            if not hicon:
                return user32.LoadIconW(None, ctypes.wintypes.LPCWSTR(32512))
            return hicon

        def _show_menu(self):
            hmenu = ctypes.windll.user32.CreatePopupMenu()
            if not hmenu:
                return

            toggle_text = "Disconnect" if self._is_connected() else "Connect"
            ctypes.windll.user32.AppendMenuW(hmenu, self.MF_STRING, self.MENU_ID_TOGGLE, toggle_text)
            ctypes.windll.user32.AppendMenuW(hmenu, self.MF_STRING, self.MENU_ID_SHOW, "Show")
            ctypes.windll.user32.AppendMenuW(hmenu, self.MF_STRING, self.MENU_ID_EXIT, "Exit")

            pt = ctypes.wintypes.POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
            ctypes.windll.user32.SetForegroundWindow(self._hwnd)
            command = ctypes.windll.user32.TrackPopupMenu(
                hmenu,
                self.TPM_RETURNCMD | self.TPM_LEFTALIGN,
                pt.x,
                pt.y,
                0,
                self._hwnd,
                None,
            )

            if command == self.MENU_ID_TOGGLE:
                self._on_toggle_connection()
            elif command == self.MENU_ID_SHOW:
                self._on_show()
            elif command == self.MENU_ID_EXIT:
                self._on_exit()

            ctypes.windll.user32.DestroyMenu(hmenu)

        def _run_loop(self):
            def_window_proc = ctypes.windll.user32.DefWindowProcW
            def_window_proc.argtypes = [
                ctypes.wintypes.HWND,
                ctypes.wintypes.UINT,
                ctypes.wintypes.WPARAM,
                ctypes.wintypes.LPARAM,
            ]
            def_window_proc.restype = ctypes.c_ssize_t

            @ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t,
                ctypes.wintypes.HWND,
                ctypes.wintypes.UINT,
                ctypes.wintypes.WPARAM,
                ctypes.wintypes.LPARAM,
            )
            def _wndproc(hwnd, msg, wparam, lparam):
                if msg == self.WM_TRAYICON:
                    if lparam == self.WM_RBUTTONUP:
                        self._show_menu()
                    elif lparam == self.WM_LBUTTONDBLCLK:
                        self._on_show()
                    return 0

                if msg == self.WM_TRAY_REFRESH:
                    self._notify_icon(self.NIM_MODIFY)
                    return 0

                if msg in (self.WM_CLOSE, self.WM_DESTROY):
                    self._notify_icon(self.NIM_DELETE)
                    ctypes.windll.user32.PostQuitMessage(0)
                    return 0

                return def_window_proc(hwnd, msg, wparam, lparam)

            self._wndproc_ref = _wndproc
            wc = _WndClassEx()
            wc.cbSize = ctypes.sizeof(_WndClassEx)
            wc.style = 0
            wc.lpfnWndProc = ctypes.cast(self._wndproc_ref, ctypes.c_void_p).value
            wc.cbClsExtra = 0
            wc.cbWndExtra = 0
            wc.hInstance = self._hinstance
            wc.hIcon = ctypes.windll.user32.LoadIconW(None, ctypes.wintypes.LPCWSTR(32512))
            wc.hCursor = ctypes.windll.user32.LoadCursorW(None, ctypes.wintypes.LPCWSTR(32512))
            wc.hbrBackground = 0
            wc.lpszMenuName = None
            wc.lpszClassName = self._class_name
            wc.hIconSm = wc.hIcon
            ctypes.windll.user32.RegisterClassExW(ctypes.byref(wc))

            self._hwnd = ctypes.windll.user32.CreateWindowExW(
                0,
                self._class_name,
                self._class_name,
                0,
                0,
                0,
                0,
                0,
                None,
                None,
                self._hinstance,
                None,
            )
            self._notify_icon(self.NIM_ADD)

            msg = ctypes.wintypes.MSG()
            while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))


class ClientGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Callsign")
        self.root.geometry("980x620")

        self.proc = None
        self._disconnect_requested = False
        self._exiting = False
        self._hidden_to_tray = False
        self.tray_icon = None
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.project_root = Path(__file__).resolve().parents[2]
        self.profile_store_path = self._profile_store_path()
        self.profiles: dict[str, dict[str, str]] = {}
        self.active_profile_name = ""
        self.startup_messages: list[str] = []
        self._connected_hint_shown = False

        self._apply_window_icon()

        self._load_profiles()

        self._build_ui()
        self._init_tray()
        self._refresh_profile_combobox(self.active_profile_name)
        if self.profile_name.get().strip():
            self._apply_profile(self.profile_name.get().strip())

        for message in self.startup_messages:
            self.append_log(message)
        self._schedule_log_pump()

    def _apply_window_icon(self):
        if os.name != "nt":
            return

        icon_path = self._resolve_app_icon_path()
        if not icon_path:
            return

        try:
            self.root.iconbitmap(default=icon_path)
        except Exception:
            # Keep default Tk icon if Windows rejects the provided icon file.
            pass

    def _resolve_app_icon_path(self) -> str:
        candidates: list[Path] = []

        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).resolve().parent
            candidates.extend([
                exe_dir / "assets" / "callsign.ico",
                exe_dir / "_internal" / "assets" / "callsign.ico",
            ])
            meipass = getattr(sys, "_MEIPASS", "")
            if meipass:
                candidates.append(Path(meipass) / "assets" / "callsign.ico")
        else:
            candidates.append(self.project_root / "assets" / "callsign.ico")

        for path in candidates:
            if path.exists():
                return str(path)
        return ""

    def _profile_store_path(self) -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent / "client_profiles.json"
        return self.project_root / "client_profiles.json"

    def _default_profiles(self) -> dict[str, dict[str, str]]:
        return {
            "local": {
                "control_url": "https://overlay.example.com",
                "access_token": os.getenv("CALLSIGN_ACCESS_TOKEN", ""),
            }
        }

    def _load_profiles(self):
        if not self.profile_store_path.exists():
            self.profiles = self._default_profiles()
            self.active_profile_name = "local"
            return

        try:
            payload = json.loads(self.profile_store_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.profiles = self._default_profiles()
            self.active_profile_name = "local"
            self.startup_messages.append(f"[gui] failed to load profiles, fallback to default: {exc}\n")
            return

        loaded_profiles = payload.get("profiles", {})
        if not isinstance(loaded_profiles, dict):
            loaded_profiles = {}

        normalized: dict[str, dict[str, str]] = {}
        for name, data in loaded_profiles.items():
            if not isinstance(name, str) or not isinstance(data, dict):
                continue
            raw_token = str(data.get("access_token", "")).strip()
            if raw_token.startswith(_DPAPI_PREFIX):
                raw_token = _dpapi_unprotect(raw_token[len(_DPAPI_PREFIX):])
            normalized[name] = {
                "control_url": str(data.get("control_url", "")).strip(),
                "access_token": raw_token,
            }

        if not normalized:
            normalized = self._default_profiles()

        self.profiles = normalized
        last_profile = str(payload.get("last_profile", "")).strip()
        if last_profile in self.profiles:
            self.active_profile_name = last_profile
        else:
            self.active_profile_name = sorted(self.profiles.keys())[0]

    def _persist_profiles(self):
        self.profile_store_path.parent.mkdir(parents=True, exist_ok=True)
        # Encrypt the access token at rest with DPAPI so the profile file does
        # not contain a plaintext bearer credential. Falls back to plaintext
        # only if DPAPI is unavailable (e.g. non-Windows).
        serialized: dict[str, dict[str, str]] = {}
        for name, data in self.profiles.items():
            token = str(data.get("access_token", ""))
            enc = _dpapi_protect(token)
            stored_token = (_DPAPI_PREFIX + enc) if enc else token
            serialized[name] = {
                "control_url": str(data.get("control_url", "")),
                "access_token": stored_token,
            }
        payload = {
            "last_profile": self.active_profile_name,
            "profiles": serialized,
        }
        self.profile_store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _refresh_profile_combobox(self, preferred_name: str = ""):
        names = sorted(self.profiles.keys())
        self.profile_combo.configure(values=names)

        current = self.profile_name.get().strip()
        if preferred_name in self.profiles:
            self.profile_name.set(preferred_name)
        elif current in self.profiles:
            self.profile_name.set(current)
        elif names:
            self.profile_name.set(names[0])
        else:
            self.profile_name.set("")

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        form = ttk.Frame(frame)
        form.pack(fill=tk.X)

        ttk.Label(form, text="Profile").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=6)
        self.profile_name = tk.StringVar(value="")
        self.profile_combo = ttk.Combobox(form, textvariable=self.profile_name, width=30, state="readonly")
        self.profile_combo.grid(row=0, column=1, sticky=tk.W, pady=6)
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)

        profile_buttons = ttk.Frame(form)
        profile_buttons.grid(row=0, column=2, sticky=tk.W, padx=(8, 0), pady=6)
        ttk.Button(profile_buttons, text="Save", command=self.save_profile).pack(side=tk.LEFT)
        ttk.Button(profile_buttons, text="Save As", command=self.save_profile_as).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(profile_buttons, text="Delete", command=self.delete_profile).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Label(form, text="Control URL").grid(row=1, column=0, sticky=tk.W, padx=(0, 8), pady=6)
        self.control_url = tk.StringVar(value="https://overlay.example.com")
        ttk.Entry(form, textvariable=self.control_url, width=70).grid(row=1, column=1, columnspan=2, sticky=tk.EW, pady=6)

        ttk.Label(form, text="Access Token").grid(row=2, column=0, sticky=tk.W, padx=(0, 8), pady=6)
        self.access_token = tk.StringVar(value=os.getenv("CALLSIGN_ACCESS_TOKEN", ""))
        ttk.Entry(form, textvariable=self.access_token, width=70, show="*").grid(row=2, column=1, columnspan=2, sticky=tk.EW, pady=6)

        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(frame)
        buttons.pack(fill=tk.X, pady=(8, 8))

        self.connect_btn = ttk.Button(buttons, text="Connect", command=self.start_client)
        self.connect_btn.pack(side=tk.LEFT)

        self.stop_btn = ttk.Button(buttons, text="Disconnect", command=self.stop_client, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.clear_btn = ttk.Button(buttons, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.exit_btn = ttk.Button(buttons, text="Exit", command=self.exit_app)
        self.exit_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.status_var = tk.StringVar(value="Status: idle")
        ttk.Label(buttons, textvariable=self.status_var).pack(side=tk.RIGHT)

        self.log_text = tk.Text(frame, height=24, wrap=tk.NONE)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_configure("success", foreground="#1f8f4c")

        x_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        x_scroll.pack(fill=tk.X)
        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        y_scroll.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
        self.log_text.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _init_tray(self):
        if os.name != "nt":
            return

        self.tray_icon = WindowsTrayIcon(
            on_show=self._post_to_main_thread(self._restore_from_tray),
            on_toggle_connection=self._post_to_main_thread(self._tray_toggle_connection),
            on_exit=self._post_to_main_thread(self.exit_app),
            is_connected=lambda: self.proc is not None,
            get_tooltip=lambda: "Callsign (connected)" if self.proc is not None else "Callsign (idle)",
        )
        self.tray_icon.start()

    def _post_to_main_thread(self, callback):
        def _wrapped():
            try:
                self.root.after(0, callback)
            except Exception:
                pass

        return _wrapped

    def _tray_toggle_connection(self):
        if self.proc is None:
            self.start_client()
        else:
            self.stop_client()

    def _refresh_tray_menu(self):
        if self.tray_icon is not None:
            self.tray_icon.update()

    def _restore_from_tray(self):
        if not self._hidden_to_tray:
            return
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self._hidden_to_tray = False

    def _hide_to_tray(self):
        self._hidden_to_tray = True
        self.root.withdraw()
        self.append_log("[gui] minimized to tray\n")

    def _stop_tray(self):
        if self.tray_icon is None:
            return
        try:
            self.tray_icon.stop()
        except Exception:
            pass
        self.tray_icon = None

    def append_log(self, text: str, tag: str | None = None):
        if tag:
            self.log_text.insert(tk.END, text, tag)
        else:
            self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _current_profile_payload(self) -> dict[str, str]:
        return {
            "control_url": self.control_url.get().strip(),
            "access_token": self.access_token.get().strip(),
        }

    def _apply_profile(self, profile_name: str):
        data = self.profiles.get(profile_name)
        if data is None:
            return
        self.control_url.set(data.get("control_url", ""))
        self.access_token.set(data.get("access_token", self.access_token.get()))
        self.active_profile_name = profile_name
        self.profile_name.set(profile_name)
        self.status_var.set(f"Status: idle | profile={profile_name}")

    def _on_profile_selected(self, _event=None):
        profile_name = self.profile_name.get().strip()
        if profile_name:
            self._apply_profile(profile_name)
            self.append_log(f"[gui] loaded profile: {profile_name}\n")

    def save_profile(self):
        profile_name = self.profile_name.get().strip()
        if not profile_name:
            return self.save_profile_as()

        self.profiles[profile_name] = self._current_profile_payload()
        self.active_profile_name = profile_name
        self._refresh_profile_combobox(profile_name)
        self._persist_profiles()
        self.append_log(f"[gui] profile saved: {profile_name}\n")

    def save_profile_as(self):
        initial_name = self.profile_name.get().strip() or "new-profile"
        profile_name = simpledialog.askstring("Save Profile", "Profile name:", initialvalue=initial_name)
        if profile_name is None:
            return
        profile_name = profile_name.strip()
        if not profile_name:
            self.append_log("[gui] profile name cannot be empty\n")
            return

        self.profiles[profile_name] = self._current_profile_payload()
        self.active_profile_name = profile_name
        self._refresh_profile_combobox(profile_name)
        self._persist_profiles()
        self.append_log(f"[gui] profile saved as: {profile_name}\n")

    def delete_profile(self):
        profile_name = self.profile_name.get().strip()
        if not profile_name or profile_name not in self.profiles:
            self.append_log("[gui] no profile selected\n")
            return

        if not messagebox.askyesno("Delete Profile", f"Delete profile '{profile_name}'?"):
            return

        self.profiles.pop(profile_name, None)
        if not self.profiles:
            self.profiles = self._default_profiles()
        self._refresh_profile_combobox()
        selected = self.profile_name.get().strip()
        if selected:
            self._apply_profile(selected)
        self._persist_profiles()
        self.append_log(f"[gui] profile deleted: {profile_name}\n")

    def _save_active_profile_snapshot(self):
        profile_name = self.profile_name.get().strip() or self.active_profile_name.strip()
        if not profile_name:
            return
        self.profiles[profile_name] = self._current_profile_payload()
        self.active_profile_name = profile_name
        self._persist_profiles()

    def _schedule_log_pump(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.append_log(line)
                if (not self._connected_hint_shown) and "[tunnel] connected" in line.lower():
                    self.append_log("[gui] √ Connected successfully. You can browse the internet now.\n", tag="success")
                    self._connected_hint_shown = True
        except queue.Empty:
            pass
        self.root.after(100, self._schedule_log_pump)

    def _is_admin(self) -> bool:
        if os.name != "nt":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def start_client(self):
        if self.proc is not None:
            return

        self._disconnect_requested = False
        self._connected_hint_shown = False

        control = self.control_url.get().strip()
        access_token = self.access_token.get().strip()

        if not control or not access_token:
            self.append_log("[gui] control/access token cannot be empty\n")
            return

        if not self._is_admin():
            self.append_log("[gui] Wintun + Apply Routes requires running GUI as Administrator\n")
            self.append_log("[gui] please restart gui_client.exe with administrator privileges\n")
            return

        self._save_active_profile_snapshot()

        env = os.environ.copy()
        env["CALLSIGN_ACCESS_TOKEN"] = access_token

        cmd, launch_cwd = self._build_agent_command(control)
        cmd.extend(["--use-wintun", "--apply-routes"])

        creationflags = 0
        startupinfo = None
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                text=True,
                cwd=launch_cwd,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
        except Exception as exc:
            self.append_log(f"[gui] failed to start client: {exc}\n")
            self.proc = None
            return

        self.status_var.set("Status: connected")
        self.connect_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.append_log("[gui] client started\n")
        self._refresh_tray_menu()

        thread = threading.Thread(target=self._read_output, daemon=True)
        thread.start()

    def _build_agent_command(self, control: str):
        args = ["--control-url", control]

        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).resolve().parent
            # In packaged mode, run agent from its own onedir bundle to keep runtime files isolated.
            agent_exe = exe_dir / "agent" / "agent.exe"
            if not agent_exe.exists():
                # Backward-compat fallback for older layouts that place agent.exe next to GUI.
                agent_exe = exe_dir / "agent.exe"
            if not agent_exe.exists():
                raise FileNotFoundError(f"agent.exe not found next to GUI: {agent_exe}")
            return [str(agent_exe), *args], str(agent_exe.parent)

        agent_script = self.project_root / "client" / "windows" / "agent.py"
        return [sys.executable, "-u", str(agent_script), *args], str(self.project_root)

    def _read_output(self):
        proc = self.proc
        if proc is None or proc.stdout is None:
            return

        for line in proc.stdout:
            self.log_queue.put(line)

        # Ensure we report a real exit code instead of a transient None.
        code = proc.wait()
        if self._disconnect_requested:
            self.log_queue.put("[gui] client disconnected\n")
        elif code == 0:
            self.log_queue.put("[gui] client exited cleanly\n")
        else:
            self.log_queue.put(f"[gui] client exited with code {code}\n")
        if self.proc is proc:
            self.proc = None
        self._disconnect_requested = False
        try:
            self.root.after(0, self._set_idle)
        except RuntimeError:
            # Tk may already be shutting down when the reader thread exits.
            pass

    def _set_idle(self):
        self._connected_hint_shown = False
        profile = self.profile_name.get().strip()
        if profile:
            self.status_var.set(f"Status: idle | profile={profile}")
        else:
            self.status_var.set("Status: idle")
        self.connect_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self._refresh_tray_menu()

    def stop_client(self):
        if self.proc is None:
            return

        self._disconnect_requested = True
        self.append_log("[gui] disconnect requested\n")

        try:
            if os.name == "nt":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

        self.proc = None
        self._set_idle()
        self.append_log("[gui] client stopped\n")

    def on_close(self):
        self._save_active_profile_snapshot()
        self._hide_to_tray()

    def exit_app(self):
        if self._exiting:
            return
        self._exiting = True
        self._save_active_profile_snapshot()
        self.stop_client()
        self._stop_tray()
        self.root.destroy()


def main():
    if not _acquire_single_instance_lock():
        _show_info_popup("Callsign is already running. You can find it in the system tray (bottom-right corner).")
        return

    try:
        if os.name == "nt":
            attempted_relaunch = "--elevated-relaunch" in sys.argv
            if not _is_admin_user():
                if attempted_relaunch:
                    _show_fatal_error("Administrator privileges were not granted. The app cannot run.")
                    return

                _show_info_popup("This app requires administrator privileges for network changes. Windows will now ask for administrator permission.")
                if _request_uac_relaunch():
                    _release_single_instance_lock()
                    return

                _show_fatal_error("Administrator privileges were not granted. The app cannot run.")
                return

        root = tk.Tk()
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        app = ClientGui(root)
        app.append_log("[gui] ready (wintun+routes always enabled)\n")
        root.mainloop()
    finally:
        _release_single_instance_lock()


def _show_fatal_error(message: str):
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(0, message, "Callsign Error", 0x10)
            return
        except Exception:
            pass
    print(message)


def _show_info_popup(message: str):
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(0, message, "Callsign", 0x40)
            return
        except Exception:
            pass
    print(message)


def _is_admin_user() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _request_uac_relaunch() -> bool:
    if os.name != "nt":
        return False

    if getattr(sys, "frozen", False):
        executable = sys.executable
        argv = ["--elevated-relaunch"]
    else:
        executable = sys.executable
        argv = [str(Path(__file__).resolve()), "--elevated-relaunch"]

    params = subprocess.list2cmdline(argv)
    work_dir = str(Path(executable).resolve().parent)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, work_dir, 1)
    return result > 32


def _acquire_single_instance_lock() -> bool:
    if os.name != "nt":
        return True

    global _single_instance_mutex
    global _single_instance_lock_file
    if _single_instance_mutex is not None:
        return True
    if _single_instance_lock_file is not None:
        return True

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = ctypes.wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    mutex_name = os.getenv("CALLSIGN_SINGLE_INSTANCE_MUTEX", "Local\\CallsignSingleInstance")
    ctypes.set_last_error(0)
    mutex = kernel32.CreateMutexW(None, False, mutex_name)
    last_error = ctypes.get_last_error()
    if mutex:
        if last_error == 183:
            kernel32.CloseHandle(mutex)
            return False
        _single_instance_mutex = mutex
        return True

    # Fallback: file lock in temp dir for environments where mutex creation fails.
    lock_file = None
    try:
        import msvcrt

        lock_name = os.getenv("CALLSIGN_SINGLE_INSTANCE_LOCKFILE", "callsign.single_instance.lock")
        lock_path = Path(tempfile.gettempdir()) / lock_name
        lock_file = lock_path.open("a+b")
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        _single_instance_lock_file = lock_file
        return True
    except Exception:
        if lock_file is not None:
            try:
                lock_file.close()
            except Exception:
                pass
        # Fail closed: if locking is unavailable, do not allow another ambiguous launch.
        return False


def _release_single_instance_lock():
    if os.name != "nt":
        return

    global _single_instance_mutex
    global _single_instance_lock_file
    if _single_instance_mutex is None:
        if _single_instance_lock_file is None:
            return

    if _single_instance_mutex is not None:
        ctypes.windll.kernel32.CloseHandle(_single_instance_mutex)
        _single_instance_mutex = None

    if _single_instance_lock_file is not None:
        try:
            import msvcrt

            _single_instance_lock_file.seek(0)
            msvcrt.locking(_single_instance_lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            _single_instance_lock_file.close()
        except Exception:
            pass
        _single_instance_lock_file = None


if __name__ == "__main__":
    try:
        main()
    except Exception:
        detail = traceback.format_exc()
        base_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
        crash_log = base_dir / "gui_client_crash.log"
        try:
            crash_log.write_text(detail, encoding="utf-8")
        except Exception:
            pass
        _show_fatal_error(f"Client crashed. See log: {crash_log}")
