# OBSIDIAN PROTOCOL — Executive Summary

**Üretim Zamanı:** 2026-06-27 11:49 UTC

| Metrik | Değer |
|---|---|
| Risk Level | **HIGH** (60.5/100) |
| Assets Affected | 1 |
| Detection Coverage | 75.0% |
| Patch Required | Yes |
| Estimated Impact | Medium-High - Saldırı yüzeyi riskli ama tespit kapasitesi mevcut |

**Özet:** 3 ayrı olay 1 kritik/yüksek önemli incident'e korele edildi.

## Recommendations

1. Otomatik yama yönetimi (örn. unattended-upgrades + staging test pipeline)
2. Güvenlik patch'lerinde regresyon test matrisine 'bilinen bypass teknikleri' eklenmeli
3. 'NetFlow / Network Traffic Metadata' toplamaya başla -> şu kör taktikleri kapatır: Lateral Movement, Command and Control, Exfiltration, Discovery

> Teknik detaylar için: `reports/obsidian_protocol_report.pdf`