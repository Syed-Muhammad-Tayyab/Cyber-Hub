// Cyber Hub built-in rules - weaponised documents & shortcuts
// Developed by Syed Muhammad Tayyab

rule Office_Macro_AutoExec_Shell
{
    meta:
        threat_name = "TrojanDownloader:O97M/AutoExecMacro"
        severity = "medium"
        description = "Office macro that runs automatically when the document opens and starts programs"
    strings:
        $vba = "_VBA_PROJECT" wide
        $vba2 = "VBA" ascii fullword
        $a1 = "AutoOpen" nocase ascii
        $a2 = "Document_Open" nocase ascii
        $a3 = "Workbook_Open" nocase ascii
        $a4 = "Auto_Open" nocase ascii
        $a5 = "AutoExec" nocase ascii
        $x1 = "WScript.Shell" nocase ascii
        $x2 = "powershell" nocase ascii
        $x3 = "URLDownloadToFile" nocase ascii
        $x4 = "Shell.Application" nocase ascii
        $x5 = "cmd.exe" nocase ascii
    condition:
        uint32(0) == 0xE011CFD0 and ($vba or $vba2) and 1 of ($a*) and 1 of ($x*)
}

rule RTF_Equation_Editor_Exploit
{
    meta:
        threat_name = "Exploit:RTF/CVE-2017-11882"
        severity = "high"
        description = "RTF that embeds the old Equation Editor object abused to run code (CVE-2017-11882 / CVE-2018-0802)"
    strings:
        $obj = "\\objdata" nocase
        $upd = "\\objupdate" nocase
        $clsid = "0002ce020000000000c000000000000046" nocase
        $eq = "equation.3" nocase
        $eqh = "4571756174696f6e2e33" nocase
    condition:
        uint32(0) == 0x74725C7B and $obj and ($clsid or $eq or $eqh) and ($upd or $clsid)
}

rule PDF_Launch_Action
{
    meta:
        threat_name = "Trojan:PDF/LaunchAction"
        severity = "medium"
        description = "PDF that tries to launch a program or command when opened"
    strings:
        $launch = "/Launch" ascii
        $c1 = "cmd.exe" nocase
        $c2 = "powershell" nocase
        $c3 = /\.(exe|bat|cmd|vbs|js|hta|scr|ps1)\b/ nocase
    condition:
        uint32(0) == 0x46445025 and $launch and any of ($c*)
}

rule LNK_Script_Launcher
{
    meta:
        threat_name = "Trojan:LNK/ScriptLauncher"
        severity = "medium"
        description = "Shortcut that starts PowerShell / mshta / a script host with hidden or download arguments"
    strings:
        $ps = "powershell" nocase ascii wide
        $mshta = "mshta" nocase ascii wide
        $ws = "wscript" nocase ascii wide
        $cs = "cscript" nocase ascii wide
        $a1 = "-w hidden" nocase ascii wide
        $a2 = "-windowstyle hidden" nocase ascii wide
        $a3 = "-enc" nocase ascii wide
        $a4 = "DownloadString" nocase ascii wide
        $a5 = "iex" fullword nocase ascii wide
        $a6 = "http" nocase ascii wide
        $a7 = "-nop" nocase ascii wide
        $a8 = "bypass" nocase ascii wide
        $a9 = "javascript:" nocase ascii wide
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 200KB and
        any of ($ps, $mshta, $ws, $cs) and 2 of ($a*)
}

rule HTML_Smuggling
{
    meta:
        threat_name = "Trojan:HTML/Smuggling"
        severity = "high"
        description = "Web page that builds a file in the browser and saves it automatically (HTML smuggling)"
    strings:
        $b1 = "new Blob(" nocase
        $b2 = "msSaveOrOpenBlob" nocase
        $b3 = "createObjectURL" nocase
        $d1 = /\.download\s*=/ nocase
        $d2 = ".click()" nocase
        $c1 = "atob(" nocase
        $c2 = "Uint8Array" nocase
        $c3 = "charCodeAt" nocase
        $big = /["'][A-Za-z0-9+\/]{1000}/                  // long encoded payload (libyara stops matching past ~1000 repeats)
    condition:
        filesize < 30MB and ($b1 or $b2) and ($b2 or ($b3 and $d1 and $d2)) and 2 of ($c*) and $big
}
