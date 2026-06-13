# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['zeus_mail.py'],
    pathex=[],
    binaries=[],
    datas=[('zeus_engine.py', '.'), ('zeus_worker.py', '.'), ('zeus_security.py', '.'), ('boleto_editor.py', '.')],
    hiddenimports=['PyQt5', 'PyQt5.QtWidgets', 'PyQt5.QtCore', 'PyQt5.QtGui', 'sqlite3', 'sklearn', 'sklearn.naive_bayes', 'sklearn.feature_extraction.text', 'reportlab', 'reportlab.pdfgen', 'reportlab.lib.colors', 'pypdf', 'pdfplumber', 'PIL', 'cryptography', 'cryptography.fernet', 'email', 'imaplib', 'smtplib', 'asyncio', 'multiprocessing', 'zeus_engine', 'zeus_worker', 'zeus_security', 'boleto_editor'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ZEUS_Debug',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
