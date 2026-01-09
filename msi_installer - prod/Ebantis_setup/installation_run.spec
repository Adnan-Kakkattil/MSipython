# -*- mode: python ; coding: utf-8 -*-

import os
 
# Path to the folder containing all compiled .pyd files

pyd_dir = r'D:\Downloads\V4EXE 1\V4EXE\Ebantis_setup copy'
 
# Include all necessary .pyd files

pyd_files = [

    (os.path.join(pyd_dir, 'autostart.cp310-win_amd64.pyd'), '.'),

    (os.path.join(pyd_dir, 'installation.cp310-win_amd64.pyd'), '.'),

    (os.path.join(pyd_dir, 'uninstallation.cp310-win_amd64.pyd'), '.'),

    (os.path.join(pyd_dir, 'utils\\service.cp310-win_amd64.pyd'), '.'),

    (os.path.join(pyd_dir, 'venv\\Lib\\site-packages\\win32\\win32service.pyd'), '.'),

]
 
# Hidden imports for everything needed in both flows

hidden_imports = [

    'win32event', 'win32serviceutil', 'encryption', 'installation', 'uninstallation',

    'pymongo', 'pyautogui', 'PyQt6', 'PyQt6.QtCore', 'PyQt6.QtWidgets', 'sqlite3', 'requests',

    'Crypto', 'Crypto.Cipher.AES', 'Crypto.Util.Padding', 'utils.service', 'utils.config',

    'update.AutoUpdaterService', 'dotenv', 'pywin32', 'psutil', 'PyJWT', 'jwt',

    'msal', 'msal.oauth2cli', 'msal.oauth2cli.assertion'

]
 
# Single Analysis for combined EXE

a = Analysis(

    ['installation_run.py'],  # Main script handles both install/uninstall

    pathex=[pyd_dir],

    binaries=pyd_files,

    datas=[],

    hiddenimports=hidden_imports,

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

    name='Ebantis-Setup',  # Single EXE name

    debug=False,

    bootloader_ignore_signals=False,

    strip=False,

    upx=True,

    upx_exclude=[],

    runtime_tmpdir=None,

    console=True,  # GUI application

    disable_windowed_traceback=False,

    argv_emulation=False,

    target_arch=None,

    codesign_identity=None,

    entitlements_file=None,

    icon=['Ebantis.ico'],

)

 