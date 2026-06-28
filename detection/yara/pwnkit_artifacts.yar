/*
    YARA Kuralı: PwnKit (CVE-2021-4034) Exploit Artifact Tespiti

    Bu kural, diskte (özellikle /tmp veya /dev/shm gibi yazılabilir
    geçici dizinlerde) PwnKit exploit'inin bıraktığı karakteristik
    artifact'leri (sahte gconv-modules dosyası, kötü amaçlı .so) arar.

    Mantık: Gerçek exploit kodlarının (örn. ryaagard'ın halka açık
    PoC'si) ürettiği evil.so dosyası, gconv() ve gconv_init()
    fonksiyonlarını belirli bir desende export eder. Normal/meşru
    gconv modülleri bu fonksiyonları farklı bir context'te
    (genelde glibc'nin kendi paketlenmiş .so'larında) barındırır,
    /tmp altında DEĞİL.

    Referans: Qualys advisory, exploit-db #50689
*/

rule PwnKit_Malicious_Gconv_Module
{
    meta:
        description = "PwnKit (CVE-2021-4034) exploit'inin diskte bıraktığı sahte gconv shared library'sini tespit eder"
        author = "obsidian-protocol-warden"
        date = "2026-06-27"
        cve = "CVE-2021-4034"
        reference = "https://www.exploit-db.com/exploits/50689"
        severity = "critical"

    strings:
        // evil.so içinde her zaman bulunan iki export edilmiş fonksiyon
        $func1 = "gconv_init" ascii
        $func2 = "gconv" ascii fullword

        // exploit.c'nin execve çağrısında kullandığı karakteristik
        // ortam değişkeni deseni
        $env_pattern = "PATH=GCONV_PATH=" ascii

        // Sahte gconv-modules dosyasının içeriği (INTERNAL modül
        // tanımı, meşru sistem dosyalarında farklı formatta olur)
        $fake_module = "module\tINTERNAL" ascii

        // setuid(0)/setgid(0)/setgroups(0) zinciri - root'a düşürme
        // sinyali, küçük .so dosyalarında nadiren görülür
        $privesc_chain = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }  // 3 ardışık call (setuid/setgid/setgroups)

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic byte
        (($func1 and $func2) or $fake_module or $env_pattern) and
        filesize < 50KB  // gerçek gconv modülleri genelde daha büyük; bu küçük, amaca özel .so
}

rule PwnKit_Exploit_Source_Artifact
{
    meta:
        description = "PwnKit exploit kaynak kodunun (C dosyası) karakteristik string desenlerini tespit eder - disk üzerinde bırakılmış kaynak dosyaları için"
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
