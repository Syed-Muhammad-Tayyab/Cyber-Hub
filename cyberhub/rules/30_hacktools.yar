// Cyber Hub built-in rules - credential theft tools
// Developed by Syed Muhammad Tayyab
// Tool strings are written as hex so this rule file is not itself flagged by other antivirus products.

rule HackTool_Credential_Dumper
{
    meta:
        threat_name = "HackTool:Win/CredentialDumper"
        severity = "high"
        description = "Contains commands of a well-known Windows password dumping tool"
    strings:
        // sekurlsa::logonpasswords
        $a1 = { 73 65 6B 75 72 6C 73 61 3A 3A 6C 6F 67 6F 6E 70 61 73 73 77 6F 72 64 73 }
        $w1 = { 73 00 65 00 6B 00 75 00 72 00 6C 00 73 00 61 00 3A 00 3A 00 6C 00 6F 00 67 00 6F 00 6E 00 70 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 73 00 }
        // lsadump::sam
        $a2 = { 6C 73 61 64 75 6D 70 3A 3A 73 61 6D }
        $w2 = { 6C 00 73 00 61 00 64 00 75 00 6D 00 70 00 3A 00 3A 00 73 00 61 00 6D 00 }
        // gentilkiwi
        $a3 = { 67 65 6E 74 69 6C 6B 69 77 69 }
        $w3 = { 67 00 65 00 6E 00 74 00 69 00 6C 00 6B 00 69 00 77 00 69 00 }
        // privilege::debug
        $a4 = { 70 72 69 76 69 6C 65 67 65 3A 3A 64 65 62 75 67 }
        $w4 = { 70 00 72 00 69 00 76 00 69 00 6C 00 65 00 67 00 65 00 3A 00 3A 00 64 00 65 00 62 00 75 00 67 00 }
    condition:
        2 of them
}

rule LSASS_Memory_Dump_Command
{
    meta:
        threat_name = "HackTool:Script/LsassDump"
        severity = "high"
        description = "Dumps the memory of lsass.exe (where Windows keeps sign-in secrets)"
    strings:
        $l = "lsass" nocase ascii wide
        $m1 = { 63 6F 6D 73 76 63 73 2E 64 6C 6C }            // comsvcs.dll
        $m2 = /comsvcs(\.dll)?["']?\s*,\s*#?(minidump|24)/ nocase
        $p1 = /procdump(64)?(\.exe)?["']?\s+[^\r\n]{0,30}-ma\s/ nocase
        $p2 = "Out-Minidump" nocase ascii wide
    condition:
        filesize < 10MB and $l and ($m2 or ($m1 and $p2) or $p1 or $p2)
}
