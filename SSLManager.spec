# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'unittest',
        'pydoc',
        'sqlite3',
        'PyQt6.QtNetwork',
        'PyQt6.QtSvg',
        'PyQt6.QtPdf',
        'PyQt6.QtOpenGL',
        'PyQt6.QtQml',
        'PyQt6.QtQuick',
        'PyQt6.QtSql',
        'PyQt6.QtTest',
        'PyQt6.QtXml',
    ],
    noarchive=False,
    optimize=1,
)

# Remove DLLs gráficas 3D/PDF/Rede e traduções não utilizadas pelo aplicativo
_UNUSED_BINARIES = (
    'opengl32sw.dll',
    'd3dcompiler_47.dll',
    'qt6pdf.dll',
    'qt6network.dll',
    'qt6svg.dll',
    'qt6opengl.dll',
    'qpdf.dll',
    'qsvg.dll',
    'qsvgicon.dll',
    'qgif.dll',
    'qwebp.dll',
    'qtiff.dll',
    'qtga.dll',
    'qwbmp.dll',
)
a.binaries = [b for b in a.binaries if not b[0].lower().endswith(_UNUSED_BINARIES)]
a.datas = [d for d in a.datas if 'translations' not in d[0].lower()]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SSLManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/app_icon.ico'],
    contents_directory='_internal',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SSLManager_runtime',
)
