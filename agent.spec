# -*- mode: python ; coding: utf-8 -*-


wintun_dll = ('third_party\\wintun\\wintun\\bin\\arm64\\wintun.dll', '.')
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
