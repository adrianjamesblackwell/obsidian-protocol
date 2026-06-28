# WARDEN MODÜLÜ — Detection Engineering
### OBSIDIAN PROTOCOL / Bu Saldırı Zinciri Nasıl Yakalanır

Bu klasör, VECTOR-I ve VECTOR-II için **gerçek, çalıştırılabilir
tespit kuralları** içerir. Amaç sadece "nasıl saldırdım" değil, "bir
SOC analisti bunu nasıl görür" sorusunu cevaplamak.

## Neden İki Farklı Tespit Stratejisi Var

| CVE | Log Kaynağı | Güvenilirlik | Neden |
|---|---|---|---|
| CVE-2021-41773/42013 | Apache access log | Yüksek | İstek HTTP seviyesinde, her zaman loglanır |
| CVE-2021-4034 (PwnKit) | **auditd (syscall)**, auth.log DEĞİL | auth.log: Düşük / auditd: Yüksek | Exploit, pkexec'in kimlik doğrulama+log kodunun **önüne** geçiyor |

PwnKit kısmı özellikle önemli bir öğrenme noktası: çoğu kişi "auth.log'a
bakarım, pkexec çalıştırıldıysa görürüm" diye düşünür. **Bu yanlış.**
Zafiyet, pkexec'in normal kimlik doğrulama/logging akışına girmeden
önce tetikleniyor. Bu yüzden `detection/sigma/pwnkit_cve_2021_4034.yml`
auditd syscall seviyesini birincil sinyal olarak kullanıyor, auth.log'u
sadece "varsa bonus" olarak işaretliyor.

## Kurulum: auditd ile PwnKit Tespiti

Range'in `target-49` (container: `obsidian-target-49`) servisinde bu tespiti test etmek için:

```bash
docker exec -it obsidian-target-49 bash
apt-get install -y auditd audispd-plugins
echo "-w /usr/bin/pkexec -p x -k pkexec_exec" >> /etc/audit/rules.d/pwnkit.rules
service auditd restart
```

PwnKit exploit'ini çalıştırdıktan sonra:
```bash
ausearch -k pkexec_exec | grep GCONV_PATH
```

Bu komut, walkthrough'un Aşama 5'inde elde ettiğin root shell'in
auditd'de nasıl göründüğünü gösterir.

## Sigma Kurallarını Test Etme

Kurallar standart Sigma formatında yazıldı, [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
veya herhangi bir Sigma-destekli SIEM'e (Splunk, Elastic, Wazuh) import
edilebilir:

```bash
pip install sigma-cli --break-system-packages
sigma convert -t splunk detection/sigma/apache_path_traversal_cve_2021_41773.yml
```

## YARA Kuralları

`detection/yara/pwnkit_artifacts.yar`, PwnKit exploit'inin diskte
bıraktığı artifact'leri (sahte `.so` dosyası, `gconv-modules` taklit
dosyası) tarar. Lab'da exploit'i çalıştırdıktan sonra test et:

```bash
yara detection/yara/pwnkit_artifacts.yar /tmp/ -r
```

## Patch / Kalıcı Çözüm

| CVE | Kalıcı Çözüm |
|---|---|
| CVE-2021-41773/42013 | Apache'yi **2.4.51+**'a yükselt. Geçici önlem: `Require all denied` varsayılanını koru, gereksiz `Alias`/`ScriptAlias` dizinlerini kapat |
| CVE-2021-4034 | `apt-get update && apt-get install policykit-1` (yamalı sürüm). Acil geçici önlem: `chmod 0755 /usr/bin/pkexec` (SUID bitini kaldır — pkexec'i kullanılamaz yapar ama zafiyeti kapatır) |

## MITRE ATT&CK Eşlemesi

| Aşama | Teknik | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Discovery | File and Directory Discovery | T1083 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Setuid/Setgid | T1548.001 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
