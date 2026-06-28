/*
    YARA Rule: PwnKit (CVE-2021-4034) Exploit Artifact Detection

    This rule looks for characteristic artifacts left on disk
    (especially in writable temporary directories such as /tmp or
    /dev/shm) by the PwnKit exploit — a forged gconv-modules file and
    a malicious .so.

    Rationale: the evil.so produced by real exploit code (e.g. the
    publicly available PoC by ryaagard) exports the gconv() and
    gconv_init() functions in a specific pattern. Legitimate gconv
    modules host these functions in a different context (typically
    glibc's own packaged .so files), and never under /tmp.

    Reference: Qualys advisory, exploit-db #50689
*/

rule PwnKit_Malicious_Gconv_Module
{
    meta:
        description = "Detects the forged gconv shared library left on disk by the PwnKit (CVE-2021-4034) exploit"
        author = "obsidian-protocol-warden"
        date = "2026-06-27"
        cve = "CVE-2021-4034"
        reference = "https://www.exploit-db.com/exploits/50689"
        severity = "critical"

    strings:
        // Two exported functions always present in evil.so
        $func1 = "gconv_init" ascii
        $func2 = "gconv" ascii fullword

        // Characteristic environment variable pattern used in
        // exploit.c's execve() call
        $env_pattern = "PATH=GCONV_PATH=" ascii

        // Content of the forged gconv-modules file (INTERNAL module
        // declaration; legitimate system files use a different format)
        $fake_module = "module\tINTERNAL" ascii

        // setuid(0)/setgid(0)/setgroups(0) chain — a privilege-drop-
        // to-root signal rarely seen in small .so files
        $privesc_chain = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }  // 3 consecutive calls (setuid/setgid/setgroups)

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic byte
        (($func1 and $func2) or $fake_module or $env_pattern) and
        filesize < 50KB  // legitimate gconv modules are typically larger; this is a small, purpose-built .so
}

rule PwnKit_Exploit_Source_Artifact
{
    meta:
        description = "Detects characteristic string patterns of the PwnKit exploit source code (C file) — for source files left on disk"
        author = "obsidian-protocol-warden"
        date = "2026-06-27"
        cve = "CVE-2021-4034"

    strings:
        $bin_path = "/usr/bin/pkexec" ascii
        $dir_const = "evildir" ascii
        $gconv_func1 = "void gconv()" ascii
        $gconv_func2 = "gconv_init()" ascii
        $setuid_chain = "setuid(0)" ascii
        $execve_sh = "execve(\"/bin/sh\"" ascii

    condition:
        $bin_path and
        2 of ($gconv_func1, $gconv_func2, $setuid_chain, $execve_sh)
}
