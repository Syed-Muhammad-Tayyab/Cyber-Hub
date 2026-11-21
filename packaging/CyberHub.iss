; ============================================================
;  Cyber Hub - Windows installer (Inno Setup 6)
;  Developed by Syed Muhammad Tayyab
;
;  1. Run build_windows.bat (creates dist\CyberHub\CyberHub.exe)
;  2. Open this file in Inno Setup and press Compile (or: iscc packaging\CyberHub.iss)
;  -> dist\CyberHub-Setup-1.0.0.exe
;
;  Installs per user (no administrator rights needed) into %LOCALAPPDATA%\Programs\Cyber Hub.
;  Your data (%LOCALAPPDATA%\CyberHub) is kept on uninstall unless you tick the box.
; ============================================================
#define AppName "Cyber Hub"
#define AppVersion "1.0.0"
#define AppPublisher "Syed Muhammad Tayyab"
#define AppURL "https://github.com/Syed-Muhammad-Tayyab"

[Setup]
AppId={{6B1E3C5A-2F4D-4C8B-9A7E-2C1B0E5D7A91}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppCopyright=(c) 2026 {#AppPublisher}
VersionInfoDescription=Cyber Hub installer - Developed by {#AppPublisher}
DefaultDirName={localappdata}\Programs\Cyber Hub
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=CyberHub-Setup-{#AppVersion}
SetupIconFile=..\ui\assets\icon.ico
UninstallDisplayIcon={app}\CyberHub.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "autostart"; Description: "Start Cyber Hub when I sign in to Windows (recommended - keeps protection on)"; GroupDescription: "Protection:"

[Files]
Source: "..\dist\CyberHub\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\CyberHub.exe"; Comment: "Developed by {#AppPublisher}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\CyberHub.exe"; Tasks: desktopicon

[Registry]
; same entry the app's own "Start with Windows" switch writes, so both stay in step
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CyberHub"; \
  ValueData: """{app}\CyberHub.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\CyberHub.exe"; Description: "Open Cyber Hub now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; close the running app (engine + tray) before files are removed
Filename: "{sys}\taskkill.exe"; Parameters: "/IM CyberHub.exe /F"; Flags: runhidden; RunOnceId: "StopCyberHub"

[Code]
var RemoveData: Boolean;
function InitializeUninstall(): Boolean;
begin
  RemoveData := MsgBox('Also delete your Cyber Hub data (settings, history, password vault, quarantine, reports, backups)?' + #13#10 +
                       'Choose No to keep it for a later reinstall.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  Result := True;
end;
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and RemoveData then
    DelTree(ExpandConstant('{localappdata}\CyberHub'), True, True, True);
end;
