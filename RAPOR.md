# AegisDNS — Gece Çalışması Raporu

**Tarih:** 12 Ağustos 2026, gece oturumu
**Depo:** `/home/linux/Desktop/DNS` — `github.com/MmTKya/DNS`

---

## Özet

Faz 0, Faz 1 ve Faz 2 tamamlandı; Faz 3'ün test edilebilir dilimi yazıldı.
Ürün bugün gerçekten çalışıyor: blocklist'leri indiriyor, derliyor ve uyguluyor;
Türkiye'nin ulusal tehdit beslemesini kendi API'sinden senkronluyor; bilinmeyen
alan adlarını araştırıp sana "engelleyeyim mi?" diye soruyor; hepsini girişli bir
panelden canlı gösteriyor.

**Commit'ler:**

| Commit | Kapsam |
|---|---|
| `cb2c9a6` | Faz 0 — iskelet: resolver, store, API, panel, paketleme |
| `a8337bc` | Faz 1 — filtreleme, feed'ler, sorgu logu, istemciler, auth, canlı panel |
| _(bu oturumun son commit'i)_ | Faz 2 — tehdit istihbaratı + Faz 3'ün ilk dilimi |

---

## Ne yapıldı

### Faz 0 — İskelet

Tek statik binary (datapath + kontrol düzlemi + panel). `internal/config` tek
doğruluk kaynağı ve `DeploymentMode` enum'u burada; resolver konfigürasyona göre
**durumsuz** — mutasyon yerine anlık görüntüden yeniden kuruluyor. Başarısız bir
reload eski konfigürasyonu geri yükleyip düğümü ayakta tutuyor.

SQLite WAL modunda, tek-writer havuzuyla; gömülü migrasyon çatısı. Installer
indirmeyi release checksum'larına (ve `cosign` varsa imzaya) karşı doğruluyor ve
ilk kurulumların çoğunu bozan port 53 çakışmasını tespit ediyor.

### Faz 1 — Filtreleme

- **Kural motoru:** düz liste / hosts / AdBlock-DNS / regex ayrıştırma. Düz
  domain kuralları sıralı hash dizilerine indirgeniyor: **kural başına ~10 bayt**
  ve GC'ye görünmez. Naif bir map 50-80 bayt/kayıt tutar — Pi'de büyük listelerin
  neden sığmadığının cevabı bu.
- **Tutarlı engelleme:** A → 0.0.0.0, AAAA → ::, geri kalan her tip → SOA'lı
  NODATA. Sadece A'yı filtrelemek, engellemenin durdurması gereken bağlantıyı
  sızdırır.
- **Feed'ler:** indirme **önce sahneleniyor**, denetleniyor, sonra canlı kopyanın
  yerine geçiyor. Bir maintainer'ın bozuk build'i veya 200 ile dönen hata sayfası
  filtrelemeyi sessizce kapatamıyor. Conditional GET + gzip + jitter.
- **Sorgu logu:** sıcak yolda hiç yazma yok — sabit bellek içi ring, zamanlayıcıyla
  batch yazım, saatlik aggregate'e rollup. `ram` modu SD kart kurulumları için.
- **İstemciler:** kimlik önce ClientID (DoH yolu / DoT SNI), sonra IP, sonra CIDR.
  Evden çıkan telefonun adresi her saat değişir; kimliği değişmez.
- **Auth:** argon2id, hash'lenmiş oturum token'ı, TOTP + kurtarma kodları.
- **Panel:** SSE ile canlı sorgu akışı (sunucuda batch'li, istemcide rAF flush'lı),
  uPlot hız grafiği, cihaz/blocklist/kural ekranları.

### Faz 2 — Tehdit istihbaratı

- **USOM/SGB connector'ı:** USOM'un düz `url-list.txt` dosyası 2026'da kapandı ve
  API'ye yönlendiriyor — hâlâ ona bakan ürünler **hiçbir şey indirmiyor**. Bu
  connector API ile konuşuyor: tam geçiş, beslemenin kendi id'leri üzerinden
  saatlik delta, ve temizlenen sitelerin engelli kalmaması için günlük reconcile.
- **Zenginleştirme:** yerel SGB tablosu (bedava, anında), sonra Safe Browsing,
  URLhaus, ThreatFox ve OTX. Hepsi ücretsiz, hepsi rate-limited; anahtarı olmayan
  kaynak sessizce devre dışı kalıyor, sorguyu düşürmüyor. Kararlar günlerce cache'li.
- **"Engelleyeyim mi?" akışı:** ağın ilk kez çözdüğü isimler kuyruğa giriyor,
  kotaları koruyacak hızda kontrol ediliyor, eşiği geçenler panelde **hangi
  kaynağın ne dediğini yazan** bir kartla Block / Allow / Ignore olarak sunuluyor.
  Otomatik engelleme var ama **varsayılan kapalı**.
- **CNAME uncloaking:** resolver zincirin tamamını görür, tarayıcı eklentisi görmez.
  Ziyaret ettiğin sitenin alt alan adının arkasına saklanan izleyici, o siteyi
  bırakıp izleyiciye döndüğü halkada engelleniyor.

### Faz 3 — İlk dilim (tamamlanmadı)

- **`internal/enforce`:** nftables kural üretimi saf fonksiyon olarak yazıldı, bu
  yüzden kernel ve root olmadan test edilebiliyor. MAC bilindiğinde MAC ile
  engelliyor (cihaz lease yenileyince kaçamasın), yoksa adresle; her iki yönde;
  yamalama yerine istenen duruma **reconcile** ediyor. DNS-only modda açıkça
  "uygulanamaz" diyor ve panele ne olduğunu doğru anlatıyor.
- **`internal/traffic`:** DNS-only modda sorgu kümelemeyle oturum/sitede-süre
  çıkarımı. Public suffix listesi kullanıyor (naif "son iki etiket" kuralı
  `co.uk`'u site sanır). Her sayı **tahmini** olarak işaretli ve sınırları
  (cache aktiviteyi gizler, süre bir alt sınırdır, bant genişliği DNS'ten
  çıkarılamaz) veriyle birlikte dönüyor.

---

## Ölçülen sayılar

| | |
|---|---|
| Derlenen kural | 599.154 (3 feed) — ~6 MB, 594 ms |
| Filtre eşleşmesi | 310 ns (100K kuralda, hit) / 212 ns (miss) |
| SGB beslemesi | 464.435 domain + 15.191 IP; API şeması ve sayfalama canlı doğrulandı, ilk tam senkron oturum bittiğinde hâlâ sürüyordu |
| SSE akışı | 5 saniyede 14 kare / 26 kayıt (sorgu başına mesaj değil) |
| Panel bundle | 274 KB / 92 KB gzip |
| Binary | ~16 MB, statik, stripped; amd64 + arm64 + armv7 |
| Test | 14 paket, `-race` temiz |

---

## Testlerin yakaladığı gerçek hatalar

1. **`.gitignore`'daki çıplak `aegisdns` deseni** `cmd/aegisdns/` dizinini de yok
   sayıyordu — `main.go` hiç commit edilmeyecekti.
2. **Feed küçülme koruması dosya zaten değiştirildikten sonra çalışıyordu.**
   İndirme staged/commit olarak ikiye ayrıldı; artık kötü güncelleme canlı kopyanın
   yerine hiç geçmiyor.
3. **hosts satırında sekme ayırıcısı** kaçırılıyordu (boşlukla aranıyordu).
4. **Gizli sekmede rAF durunca** SSE tamponu sınırsız büyüyordu.
5. **SGB reconcile'ı saniye çözünürlüğündeki zaman damgasına dayanıyordu** — aynı
   saniyedeki iki senkron karşılaştırmayı bozuyordu; artan senkron kuşağına geçildi.
6. **Elle `Accept-Encoding: gzip`** göndermek Go'nun şeffaf açmasını devre dışı
   bırakıyor, SGB yanıtları sıkıştırılmış geliyordu. Canlı test yakaladı; regresyon
   testi eklendi.

---

## Doğrulanmayanlar — dürüst liste

- **Port 53, systemd unit'i ve installer'ın gerçek kurulumu** bu makinede
  denenemiyor: sudo etkileşimsiz oturumda parola istiyor ve 53'ü systemd-resolved
  tutuyor. Pi'de veya bir test makinesinde doğrulanmalı.
- **Şifreli taşımalar (DoT/DoH/DoQ)** kodlandı, config doğrulaması var, ama gerçek
  sertifikayla hiç ayağa kaldırılmadı.
- **Uzak tehdit kaynakları (Safe Browsing, URLhaus, ThreatFox, OTX)** API anahtarı
  olmadığı için canlı çağrıyla test edilmedi; yalnız "anahtarsız kaynak devre dışı
  kalır" yolu test edildi. Anahtarları panelden girince gerçek yanıtlarla
  doğrulanmalı.
- **nftables enforcement'ı** yalnız kural üretimi seviyesinde test edildi; gerçek
  bir gateway kurulumunda hiç uygulanmadı.
- **Saatlik query-log rollup'ının** kendi testi yok.
- **Panelin görsel render'ı** doğrulanamadı (tarayıcı paneli kompozit etmiyor);
  veri akışı JS ile ölçülerek doğrulandı.

---

## Sıradaki adımlar

1. **Faz 3'ü bitir:** eBPF/nftables ile gerçek per-client bant genişliği, conntrack
   canlı bağlantılar, gateway modunda gerçek internet kesme. Bunlar gerçek bir
   gateway makinesi gerektiriyor.
2. **Faz 4:** VRRP ile HA, config replikasyonu, watchdog, backup/restore.
3. **Faz 5:** WireGuard peer yönetimi, Cloudflare Tunnel, egress profilleri.
4. **Faz 6:** bildirimler, imzalı self-update, RBAC + audit log.

Ayrıca kısa vadede değerli olanlar: tehdit kaynağı anahtarlarını panelden girmek
için bir ayarlar ekranı, ve Pi'de gerçek donanım üzerinde bir duman testi.
