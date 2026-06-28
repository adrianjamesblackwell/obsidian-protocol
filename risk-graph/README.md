# RISK GRAPH
### OBSIDIAN PROTOCOL / Attack Path Visualization

## Problem

Risk raporları genelde düz tablo formatındadır ("CVE-X: Yüksek").
Yönetim ve mimarlar için en kritik soru çoğu zaman bir tablo sorusu
değil, bir **yol** sorusudur: "saldırgan internetten veritabanına
nasıl ulaşır?"

## Çözüm

`risk_graph.py`, gerçek saldırı zincirini (VECTOR-I → VECTOR-II,
Risk Engine'den gerçek skorlarla) + olası bir genişleme senaryosunu
(credential dump → lateral movement → database) tek bir yönlü graph
(DAG) olarak üretir.

## Gerçek vs Varsayımsal Ayrımı (Kritik)

Graph'taki düğümler iki tipe ayrılır:

- **Gerçek (confirmed=True):** `internet → target49 → shell → root`
  zinciri — bu lab'da **gerçekten exploit edilmiş**, kanıtı
  `docs/walkthrough.md`'de var.
- **Varsayımsal (confirmed=False):** `root → creddump → lateral →
  database` — bu segment **hiçbir zaman exploit edilmemiştir**, sadece
  "eğer zincir buradan devam etseydi nasıl görünürdü" projeksiyonu.

Mermaid çıktısında bu ayrım görsel olarak da kodlanmış: gerçek
adımlar düz çizgi + koyu renk, varsayımsal adımlar kesikli çizgi +
gri/soluk renk. Bu ayrımı gizlemek, bir raporun en tehlikeli
hatalarından biridir — "olası" ile "kanıtlanmış"ı karıştırmak.

## Kullanım

```bash
python3 risk-graph/risk_graph.py
```

Çıktı: `docs/risk-graph.mermaid` (GitHub'da otomatik render olur),
`risk-graph/output/risk_graph.json` (ham node/edge listesi — Neo4j,
Gephi gibi araçlara aktarılabilir).

## Bilinen Sınırlama

Graph şu an statik/elle tanımlı (`build_graph()` fonksiyonu sabit bir
zincir kuruyor). Gerçek bir üretim sisteminde bu, Correlation Engine'in
ürettiği `correlated_incidents.json`'dan **dinamik olarak** inşa edilir
— her incident bir edge, her aktör/varlık bir node olur. Bu projede
bilinçli olarak basit/statik tutuldu çünkü amaç metodolojiyi göstermek.
