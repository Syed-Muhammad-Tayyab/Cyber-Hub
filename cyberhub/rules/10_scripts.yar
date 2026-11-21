// Cyber Hub built-in rules - malicious scripts & living-off-the-land commands
// Developed by Syed Muhammad Tayyab

rule PS_Download_Cradle
{
    meta:
        threat_name = "Trojan:PowerShell/DownloadCradle"
        severity = "high"
        description = "PowerShell downloads a script from the internet and runs it straight from memory"
        author = "Syed Muhammad Tayyab"
    strings:
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadData" nocase ascii wide
        $dl3 = "Invoke-WebRequest" nocase ascii wide
        $dl4 = "Invoke-RestMethod" nocase ascii wide
        $dl5 = "Net.WebClient" nocase ascii wide
        $ex1 = "IEX" fullword ascii wide
        $ex2 = "Invoke-Expression" nocase ascii wide
        $ex3 = /\|\s*iex\b/ nocase
        $ex4 = "[ScriptBlock]::Create" nocase ascii wide
    condition:
        filesize < 5MB and 1 of ($dl*) and 1 of ($ex*)
}

rule PS_Encoded_Command_Launcher
{
    meta:
        threat_name = "Trojan:Script/EncodedPowerShell"
        severity = "medium"
        description = "Starts PowerShell with a long base64-encoded command (hides what it runs)"
    strings:
        $enc = /powershell(\.exe)?["']?\s[^\r\n]{0,120}\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{60,}/ nocase
        $enc2 = /pwsh(\.exe)?["']?\s[^\r\n]{0,120}\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{60,}/ nocase
    condition:
        filesize < 5MB and any of them
}

rule Script_Defender_Tampering
{
    meta:
        threat_name = "Trojan:Script/DefenderTamper"
        severity = "high"
        description = "Turns off Microsoft Defender protection or excludes folders from it"
    strings:
        $mp1 = "Set-MpPreference" nocase ascii wide
        $mp2 = "Add-MpPreference" nocase ascii wide
        $d1 = "-DisableRealtimeMonitoring" nocase ascii wide
        $d2 = "-DisableBehaviorMonitoring" nocase ascii wide
        $d3 = "-DisableIOAVProtection" nocase ascii wide
        $d4 = "-DisableScriptScanning" nocase ascii wide
        $d5 = "-ExclusionPath" nocase ascii wide
        $d6 = "-ExclusionProcess" nocase ascii wide
        $reg = "\\Windows Defender\\DisableAntiSpyware" nocase ascii wide
    condition:
        filesize < 10MB and ((1 of ($mp*) and 1 of ($d*)) or $reg)
}

rule Ransomware_Backup_Destruction
{
    meta:
        threat_name = "Ransom:Script/ShadowCopyDelete"
        severity = "critical"
        description = "Deletes Windows shadow copies / backups and disables recovery - a ransomware preparation step"
    strings:
        $v1 = /vssadmin(\.exe)?["']?\s+delete\s+shadows/ nocase
        $v2 = /wmic(\.exe)?["']?\s+shadowcopy\s+delete/ nocase
        $v3 = /wbadmin(\.exe)?["']?\s+delete\s+(catalog|systemstatebackup)/ nocase
        $v4 = /bcdedit(\.exe)?["']?\s+\/set\s+\{?default\}?\s+recoveryenabled\s+no/ nocase
        $v5 = /bcdedit(\.exe)?["']?\s+\/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures/ nocase
        $v6 = "Win32_ShadowCopy" nocase ascii wide
        $v7 = "vssadmin.exe delete shadows" nocase wide
    condition:
        filesize < 20MB and 2 of them
}

rule VBS_JS_Dropper
{
    meta:
        threat_name = "TrojanDownloader:Script/Dropper"
        severity = "high"
        description = "VBScript / JScript that downloads a file, saves it and runs it"
    strings:
        $o1 = "CreateObject" nocase
        $o2 = "ActiveXObject" nocase
        $h1 = "MSXML2.XMLHTTP" nocase
        $h2 = "WinHttp.WinHttpRequest" nocase
        $h3 = "Microsoft.XMLHTTP" nocase
        $s1 = "ADODB.Stream" nocase
        $s2 = "SaveToFile" nocase
        $r1 = "WScript.Shell" nocase
        $r2 = "Shell.Application" nocase
        $x1 = ".Run" nocase
        $x2 = "ShellExecute" nocase
        $x3 = ".Exec(" nocase
    condition:
        filesize < 2MB and 1 of ($o*) and 1 of ($h*) and 1 of ($s*) and 1 of ($r*) and 1 of ($x*)
}

rule HTA_Script_Launcher
{
    meta:
        threat_name = "Trojan:HTA/ScriptLauncher"
        severity = "high"
        description = "HTML Application that runs commands through WScript.Shell or PowerShell"
    strings:
        $hta = "<hta:application" nocase
        $ax = "ActiveXObject" nocase
        $cs = "CreateObject" nocase
        $sh = "WScript.Shell" nocase
        $ps = "powershell" nocase
        $cmd = "cmd.exe /c" nocase
    condition:
        filesize < 5MB and ($hta or extension iequals ".hta") and ($ax or $cs) and ($sh or $ps or $cmd)
}

rule Reverse_Shell_OneLiner
{
    meta:
        threat_name = "Backdoor:Script/ReverseShell"
        severity = "high"
        description = "Connects back to an attacker and hands over a command shell"
    strings:
        $b1 = /bash\s+-i\s+>&\s*\/dev\/tcp\// nocase
        $b2 = /\/bin\/(ba)?sh\s+-i\s+[0-9]?>&\s*\/dev\/tcp\// nocase
        $n1 = /\bnc(at)?\s+(-[a-z]+\s+)*-e\s+\/bin\/(ba)?sh/ nocase
        $n2 = /\bnc(at)?(\.exe)?\s+(-[a-z]+\s+)*-e\s+cmd(\.exe)?/ nocase
        $p1 = "socket.socket(" ascii
        $p2 = "os.dup2(" ascii
        $p3 = "subprocess" ascii
        $w1 = "Net.Sockets.TCPClient" nocase ascii wide
        $w2 = "GetStream()" nocase ascii wide
        $w3 = "Invoke-Expression" nocase ascii wide
        $w4 = "iex" fullword nocase ascii wide
    condition:
        filesize < 2MB and (any of ($b*) or any of ($n*) or all of ($p*) or ($w1 and $w2 and ($w3 or $w4)))
}

rule LOLBin_Remote_Payload
{
    meta:
        threat_name = "TrojanDownloader:Script/LOLBin"
        severity = "medium"
        description = "Uses a built-in Windows tool (certutil, bitsadmin, mshta, regsvr32) to fetch or run a remote payload"
    strings:
        $c1 = /certutil(\.exe)?["']?\s+[^\r\n]{0,40}-urlcache\s+[^\r\n]{0,40}http/ nocase
        $c2 = /certutil(\.exe)?["']?\s+[^\r\n]{0,40}-decode\s/ nocase
        $b1 = /bitsadmin(\.exe)?["']?\s+[^\r\n]{0,40}\/transfer\s+[^\r\n]{0,80}http/ nocase
        $m1 = /mshta(\.exe)?["']?\s+["']?(http|javascript:|vbscript:)/ nocase
        $r1 = /regsvr32(\.exe)?["']?\s+[^\r\n]{0,40}\/i:\s*http/ nocase
        $r2 = /rundll32(\.exe)?["']?\s+[^\r\n]{0,20}javascript:/ nocase
    condition:
        filesize < 5MB and any of them
}
