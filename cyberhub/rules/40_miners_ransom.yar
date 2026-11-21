// Cyber Hub built-in rules - coin miners & ransom notes
// Developed by Syed Muhammad Tayyab

rule PUA_CoinMiner
{
    meta:
        threat_name = "PUA:Win/CoinMiner"
        severity = "medium"
        description = "Cryptocurrency miner (uses your CPU / GPU to mine for someone else)"
    strings:
        $s1 = "stratum+tcp://" nocase ascii wide
        $s2 = "stratum+ssl://" nocase ascii wide
        $s3 = "stratum2+tcp://" nocase ascii wide
        $m1 = "xmrig" nocase ascii wide
        $m2 = "--donate-level" nocase ascii wide
        $m3 = "cryptonight" nocase ascii wide
        $m4 = "randomx" nocase ascii wide
        $m5 = "\"nicehash\"" nocase ascii
        $m6 = "--cpu-priority" nocase ascii wide
    condition:
        1 of ($s*) and 1 of ($m*)
}

rule Ransom_Note
{
    meta:
        threat_name = "Ransom:Text/RansomNote"
        severity = "high"
        description = "Ransom note: says your files were encrypted and asks for payment"
    strings:
        $e1 = "files have been encrypted" nocase ascii wide
        $e2 = "files are encrypted" nocase ascii wide
        $e3 = "files were encrypted" nocase ascii wide
        $e4 = "have been locked" nocase ascii wide
        $p1 = "bitcoin" nocase ascii wide
        $p2 = "BTC" fullword ascii wide
        $p3 = "monero" nocase ascii wide
        $p4 = ".onion" nocase ascii wide
        $p5 = "tor browser" nocase ascii wide
        $d1 = "decrypt" nocase ascii wide
        $d2 = "decryption" nocase ascii wide
        $d3 = "private key" nocase ascii wide
    condition:
        filesize < 2MB and 1 of ($e*) and 1 of ($p*) and 1 of ($d*)
}
