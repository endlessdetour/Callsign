# -*- mode: python ; coding: utf-8 -*-

import platform

# Select the Wintun DLL that matches the host architecture so the bundled
# driver is correct for the build target (arm64, amd64/x64, or x86).
_WINTUN_ARCH_MAP = {
    'ARM64': 'arm64',
    'AARCH64': 'arm64',
    'AMD64': 'amd64',
    'X86_64': 'amd64',
    'X86': 'x86',
    'I386': 'x86',
    'I686': 'x86',
}
_wintun_arch = _WINTUN_ARCH_MAP.get(platform.machine().upper(), 'amd64')

wintun_dll = ('third_party\\wintun\\wintun\\bin\\%s\\wintun.dll' % _wintun_arch, '.')
wintun_license = ('third_party\\wintun\\wintun\\LICENSE.txt', 'third_party\\wintun')

a = Analysis(
    ['client\\windows\\agent.py'],
    pathex=[],
    binaries=[],
    datas=[wintun_dll, wintun_license],
    hiddenimports=['_overlapped', 'pkgutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=True,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='agent',
)
