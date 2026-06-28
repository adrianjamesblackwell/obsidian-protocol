# Gerekli auditd Kuralı

Bu dosya, `pwnkit_cve_2021_4034.yml` Sigma kuralının veri kaynağını
üretmek için **zorunlu ön koşulu** açıklıyor.

`/etc/audit/rules.d/pwnkit.rules` içine eklenmeli:

```
-w /usr/bin/pkexec -p x -k pkexec_exec
```

Bu olmadan, `auditd` `pkexec` çalıştırmalarını hiç loglamaz ve Sigma
kuralındaki `selection_auditd_primary` / `selection_auditd_env`
koşulları hiçbir zaman tetiklenmez — yani kural "doğru" olsa da, veri
kaynağı (auditd log) hiç üretilmediği için sessiz kalır.

Detaylı kurulum adımları için: [`detection/README.md`](../README.md#kurulum-auditd-ile-pwnkit-tespiti)
