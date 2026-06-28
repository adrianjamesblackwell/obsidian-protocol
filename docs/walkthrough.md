# OBSIDIAN PROTOCOL — Operasyon Günlüğü
### Saldırı Zinciri: TARGET-49'un Düşüşü

> **Format notu:** Bu doküman bir komut listesi değil, kronolojik bir
> operasyon günlüğü. Her aşamada üç şeyi bulacaksın: **durum** (senaryo),
> **kök neden analizi** (neden işe yarıyor), ve **operatör görevi**
> (çözümü vermeyen, yön veren talimat). Cevap kağıdı değil bu —
> sıkışırsan ipucu kutularına bak, ama exploit kodunu sen yazacaksın.

---

## Durum Brifingi

**OPERATOR**, range'deki **TARGET-49**'a karşı konuşlandırılıyor.
Dışarıdan göründüğü kadarıyla sıradan bir Apache kurulumu — ama
versiyon banner'ı dikkat çekiyor: **2.4.49**. Ekim 2021'de yayınlanmış,
sadece birkaç hafta yaşamış bir sürüm. Bu pencere içinde, Apache'nin
path normalization mantığında ciddi bir regresyon vardı.

TARGET-49'un attack surface'i şu an tek bir şey: **HTTP**. Ama bu
katmandan, doğru zincirle, root shell'e kadar gidilecek.

```
[RECON]  →  VECTOR-I [INITIAL ACCESS via path traversal → RCE]  →
[FOOTHOLD]  →  [LOCAL ENUMERATION]  →
VECTOR-II [PRIVILEGE ESCALATION via PwnKit]  →  [ROOT — OPERASYON TAMAMLANDI]
```

MITRE ATT&CK eşlemesi:

| Aşama | Taktik | Teknik |
|---|---|---|
| Recon | Reconnaissance | T1595 (Active Scanning) |
| VECTOR-I | Initial Access | T1190 (Exploit Public-Facing Application) |
| VECTOR-I | Execution | T1059 (Command and Scripting Interpreter) |
| VECTOR-II | Privilege Escalation | T1548.001, T1068 |

---

## Aşama 0: Range'i Devreye Al

```bash
./setup.sh
# veya manuel:
docker-compose up -d
docker exec -it obsidian-operator bash
```

OPERATOR kutusundan TARGET-49'a DNS ile erişebilirsin — compose,
servis adını (`target-49`) otomatik çözer.

---

## Aşama 1: Recon — "TARGET-49 Gerçekten O Zafiyetli Sürüm mü?"

**Durum:** İlk iş, varsayımda bulunmamak. Banner'da "Apache/2.4.49"
görmek heyecan verici ama gerçek bir operatör (ve sen) bunu doğrular —
banner spoof edilebilir, ya da hedef zafiyetli sürümde olsa bile
**konfigürasyon** zafiyeti tetiklemeye izin vermeyebilir.

**Kök neden bağlamı:** VECTOR-I sadece versiyon meselesi değil — bir
**konfigürasyon ön koşulu** da var. Apache'nin resmi advisory'sinde
özellikle belirtildiği gibi, bu zafiyet ancak `Require all denied`
varsayılanı dışına çıkılmış sistemlerde tetiklenebiliyor.

**Operatör görevi:**
- Apache sürümünü HTTP header'larından veya `nmap -sV` ile doğrula
- `/cgi-bin/` dizininin var olup olmadığını kontrol et — mod_cgi'nin
  aktif olup olmadığına dair ilk sinyal
- **Soru:** Sadece versiyon banner'ına güvenip RCE denemeye geçmek
  neden riskli?

---

## VECTOR-I — Aşama 2: Initial Access (Path Traversal)

**Durum:** Şimdi sıra geldi VECTOR-I'i tetiklemeye. Hedef, Apache'nin
`DocumentRoot` dışındaki dosyaları **okuyup okuyamayacağını** test
etmek. Önce zararsız bir hedefle (range'in koyduğu sahte secrets
dosyası) kanıtlayacaksın.

**Kök neden — burası kritik, atlamadan oku:** Apache 2.4.49'da path
normalization fonksiyonu yeniden yazıldı. Yeni kod, URL'deki encoded
karakterleri **tek seferde** çözüyordu. `%2e` → `.` çevriliyor, sonuç
`..` oluşuyor, ve bu reddediliyordu. **Ama** bu encoding'i bir kademe
daha derinleştirirsen (`%%32%65` gibi), normalization fonksiyonu bunu
çözmeden traversal kontrolünü yapıyordu. Kontrol geçtikten **sonra**
asıl decode işlemi gerçekleşiyordu — kontrol, henüz var olmayan `../`
dizisine bakıyordu.

Bu yüzden **CISA'nın resmi notu önemli**: orijinal CVE-2021-41773
patch'i sadece tek-seviye encoding'i düzeltti. Apache'nin ilk fix'i
yetersiz kaldığı için CISA, ikinci bir CVE numarası (CVE-2021-42013)
açmak zorunda kaldı.

**Operatör görevi:**
- `ScriptAlias` ile eşleşen bir path (`/cgi-bin/...`) üzerinden,
  encode edilmiş `../` dizileriyle traversal dene
- Önce tek-encode dene, çalışmazsa **double-encode** dene — bu,
  CVE-2021-41773 vs 42013 ayrımını bizzat görmen demek
- **Doğrulama:** `/opt/internal/secrets.env` içeriğini HTTP
  response'unda görebiliyorsan, VECTOR-I'in ilk aşaması başarılı

> **İpucu kutusu:** `/cgi-bin/` öneki + encoded traversal + hedef
> dosya yolu kombinasyonunu dene. ScriptAlias path'i kullanman şart.

---

## VECTOR-I — Aşama 3: Execution (Okumadan Çalıştırmaya Sıçrama)

**Durum:** Dosya okuyabiliyorsun. Soru şu: **bu okuma yeteneğini komut
çalıştırmaya nasıl çevirirsin?**

**Kök neden:** mod_cgi aktifken, Apache belirli path'lere gelen
istekleri "bu bir CGI script, çalıştır" diye yorumlar. Traversal ile
path'i sistemde zaten var olan bir interpreter'a (`/bin/sh` gibi)
yönlendirip, request body'sini "bu script'e girdi" gibi gönderirsen,
Apache bu body'yi **shell'e komut olarak besler.**

**Operatör görevi:**
- POST request ile, traversal path'ini bir shell interpreter'a
  yönlendirip body'de zararsız bir komut (`id`, `whoami`) çalıştırmayı
  dene
- **Kritik soru:** Bu komut hangi kullanıcı olarak çalışıyor?
  Dockerfile'a geri dön — TARGET-49'da Apache hangi kullanıcı altında
  çalışıyor?

> **İpucu kutusu:** Content-Type header'ını CGI'nin script gibi
> yorumlayacağı şekilde ayarlaman ve body'de komutunu (`echo; id`)
> vermen gerekiyor.

---

## Aşama 4: Foothold — Shell'i Stabilize Etmek

**Durum:** RCE elde edildi (VECTOR-I tamamlandı) ama her komutu tek
seferlik HTTP isteğiyle göndermek hem yavaş hem kırılgan. Burada
**interaktif bir shell**'e geçilir.

**Operatör görevi:**
- OPERATOR kutusunda bir listener aç (reverse shell senaryosu — range
  izole olduğu için bağlantı sadece `obsidian-range` içinde kalır)
- RCE üzerinden, TARGET-49'dan bu listener'a bağlanacak bir reverse
  shell tetikle
- Shell'i stabilize et

**Doğrulama:** `id` çalıştırdığında `labuser` görmen gerekiyor.

---

## Aşama 5: Local Enumeration

**Durum:** `labuser` olarak bir shell var ama bu yeterli değil. Burada
sistematik bir keşif yapılır: SUID binary'ler, sudo izinleri, kurulu
paketler.

**Operatör görevi:**
- `ls -la /usr/bin/pkexec` ile SUID bitini doğrula (`-rwsr-xr-x`)
- `dpkg -l | grep policykit` ile sürümü doğrula

---

## VECTOR-II — Aşama 6: Privilege Escalation (PwnKit'in Anatomisi)

**Durum:** Burası operasyonun en öğretici kısmı, çünkü PwnKit bir
**buffer overflow değil** — bir **mantık hatası**.

**Kök neden — detaylı:**

`pkexec`, normal kullanımda her zaman en az bir argümanla çağrılır.
`pkexec`'in C kodu, argümanları işlerken `argv[1]`'den başlayan bir
döngü kullanıyordu — `argv[0]` atlanıyordu, mantıklı bir varsayımla:
"argc en az 1'dir."

Ama `execve()` sistem çağrısını **doğrudan**, argv dizisini tamamen
boş (`argc=0`) bırakarak çağırırsan, bu varsayım çöker. `pkexec`
artık var olmayan `argv[1]`'i okumaya çalışır ve bellek sınırlarının
dışına taşar — bu bir **out-of-bounds read/write**. Taşan kısım,
process'in **environment variable** dizisine denk geliyor.

Burada devreye `GCONV_PATH` giriyor: glibc, karakter seti dönüşümü
yaparken `GCONV_PATH` değişkenindeki dizinlere bakıp uygun bir "gconv
modülü" (`.so` dosyası) yükler. Geçersiz bir `CHARSET` değeri
verirsen, glibc bu dönüşümü yapacak bir modül aramaya başlar — ve
`GCONV_PATH`'i kontrol ettiğin bir dizine işaret ettirirsen, **kendi
yazdığın `.so` dosyasını** root yetkisiyle çalıştırmasını sağlarsın.

**Bunun bu kadar güçlü olmasının sebebi:** Bu kod yolu, `pkexec`'in
normal yetki kontrolünden **önce** çalışıyor. Exploit, kimlik
doğrulama mantığına hiç girmiyor — bu da onu hem trivially
exploitable hem de (WARDEN modülünde göreceğin gibi) auth log'larda
**görünmez** yapıyor.

**Operatör görevi:**
- `execve()`'yi argv dizisi boş olacak şekilde çağıran bir C programı
  yazman gerekiyor
- Sahte bir `gconv-modules` dosyası ve onu "modül" gibi gösterecek bir
  `.so` dosyası hazırlaman gerekiyor — bu `.so` içinde, root
  yetkisiyle çalışacak `gconv_init()` fonksiyonu `setuid(0)` + shell
  spawn etmeli

> **İpucu kutusu:** Qualys'in orijinal teknik advisory'si (2022-01-25)
> bu zincirin her adımını açıklıyor. Anahtar kelimeler: `GCONV_PATH`,
> `gconv-modules` dosya formatı, `CHARSET` environment variable.

**Doğrulama:** Exploit öncesi `id` → `uid=1000(labuser)`. Exploit
sonrası `id` → `uid=0(root)`. **OPERASYON TAMAMLANDI.**

---

## Aşama 7: Kanıt Toplama ve Zaman Çizelgesi

`reports/exploitation-evidence.md` şablonunu doldururken zaman
damgalarını unutma — bu, operasyon raporunun en önemli kanıtı.

---

## Geriye Dönüp Bakış: Bu Zincir Neden "Gerçekçi"?

VECTOR-I + VECTOR-II'nin birleşimi, gerçek dünyadaki standart saldırı
yapısını yansıtıyor: dış yüzeyden RCE ile içeri gir, sonra local
privilege escalation ile genişlet. Gerçek kampanya verisi (AndroxGh0st
botnet dahil) için `docs/threat-intelligence.md`'ye geç. Bu saldırının
nasıl yakalandığını incelemek için `detection/README.md` (WARDEN
modülü).
