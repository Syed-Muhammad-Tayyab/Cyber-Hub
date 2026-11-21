// Cyber Hub built-in rules - web shells (developers / website owners)
// Developed by Syed Muhammad Tayyab

rule PHP_Webshell_Eval_Obfuscated
{
    meta:
        threat_name = "Backdoor:PHP/WebShell.Eval"
        severity = "high"
        description = "PHP that evaluates decoded / decompressed code - typical hidden web shell"
    strings:
        $php = "<?php" nocase
        $php2 = "<?=" ascii
        $e1 = /(eval|assert)\s*\(\s*(@\s*)?(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode|hex2bin)\s*\(/ nocase
        $e2 = /(eval|assert)\s*\(\s*(@\s*)?\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $e3 = /preg_replace\s*\(\s*["'][^"']{1,40}\/e["']/ nocase
        $e4 = /create_function\s*\(\s*["']{2}\s*,\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
    condition:
        filesize < 3MB and ($php or $php2) and any of ($e*)
}

rule PHP_Webshell_Command_Exec
{
    meta:
        threat_name = "Backdoor:PHP/WebShell.Exec"
        severity = "high"
        description = "PHP that runs operating-system commands taken straight from the web request"
    strings:
        $php = "<?php" nocase
        $php2 = "<?=" ascii
        $x = /(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $bt = /`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 3MB and ($php or $php2) and ($x or $bt)
}

rule ASPX_Webshell
{
    meta:
        threat_name = "Backdoor:ASP/WebShell"
        severity = "high"
        description = "ASP.NET page that starts cmd.exe / PowerShell with input from the request"
    strings:
        $asp = "<%@" ascii
        $asp2 = "runat=\"server\"" nocase
        $p1 = "Process.Start" nocase
        $p2 = "ProcessStartInfo" nocase
        $c1 = "cmd.exe" nocase
        $c2 = "powershell" nocase
        $r1 = "Request.Form" nocase
        $r2 = "Request.QueryString" nocase
        $r3 = "Request[" nocase
        $r4 = "Request.Item" nocase
    condition:
        filesize < 2MB and ($asp or $asp2) and 1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}

rule JSP_Webshell
{
    meta:
        threat_name = "Backdoor:Java/JSPWebShell"
        severity = "high"
        description = "JSP page that runs a command from a request parameter"
    strings:
        $jsp = "<%" ascii
        $x1 = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/ nocase
        $x2 = /new\s+ProcessBuilder\s*\([^)]{0,80}request\.getParameter/ nocase
    condition:
        filesize < 2MB and $jsp and any of ($x*)
}
