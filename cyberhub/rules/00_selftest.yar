// Cyber Hub built-in rules - self test
// Developed by Syed Muhammad Tayyab
//
// A harmless marker string, like the EICAR file for the YARA engine. Put the
// text CYBERHUB-RULES-ENGINE-TEST-STRING in any file and Cyber Hub reports it.

rule CyberHub_RulesEngine_TestFile
{
    meta:
        threat_name = "CyberHub-Rules-Test (not a threat)"
        severity = "low"
        description = "Rules engine test marker - proves YARA scanning works"
        author = "Syed Muhammad Tayyab"
    strings:
        $marker = "CYBERHUB-RULES-ENGINE-TEST-STRING" ascii wide
    condition:
        $marker
}
