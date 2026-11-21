# -*- mode: python ; coding: utf-8 -*-
"""
Cyber Hub - PyInstaller build recipe (Part 20)
Developed by Syed Muhammad Tayyab

    pyinstaller --noconfirm packaging\\CyberHub.spec      (or just run build_windows.bat)

Result: dist\\CyberHub\\CyberHub.exe + everything it needs in the same folder (one-folder build: starts fast,
no unpacking to %TEMP% on every start, and antivirus products trust it more than one-file builds).
Package data that MUST travel with the code (see the roadmap notes of Parts 8 and 12):
    cyberhub/rules/*.yar               built-in YARA rule pack
    cyberhub/data/eff_large_wordlist.txt   passphrase generator words
    ui/                                the user interface
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent          # noqa: F821 - provided by PyInstaller

datas = [
    (str(ROOT / "cyberhub" / "rules"), "cyberhub/rules"),
    (str(ROOT / "cyberhub" / "data"), "cyberhub/data"),
    (str(ROOT / "ui"), "ui"),
]
datas += collect_data_files("zxcvbn")            # its frequency lists
hidden = (collect_submodules("cyberhub") + collect_submodules("uvicorn") + collect_submodules("webview")
          + ["pystray._win32", "PIL._tkinter_finder"])

a = Analysis(                                    # noqa: F821
    [str(ROOT / "CyberHub.pyw")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "pytest", "IPython", "matplotlib", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)                                # noqa: F821
exe = EXE(                                       # noqa: F821
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="CyberHub",
    icon=str(ROOT / "ui" / "assets" / "icon.ico"),
    console=False,                               # a window app - no black console
    version=str(ROOT / "packaging" / "version_info.txt"),
    uac_admin=False,                             # starts as the user; firewall / system fixes ask for admin when needed
)
coll = COLLECT(                                  # noqa: F821
    exe, a.binaries, a.datas,
    name="CyberHub",
    contents_directory=".",                      # keep everything beside CyberHub.exe (own-folder checks rely on it)
)
