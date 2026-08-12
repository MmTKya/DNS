# AegisDNS — Gece Çalışması Raporu

**Tarih:** 12 Ağustos 2026, gece oturumu
**Depo:** `/home/linux/Desktop/DNS` — `github.com/MmTKya/DNS`

---

## Özet

Faz 0, Faz 1 ve Faz 2 tamamlandı; Faz 3'ün cihaz kimliği ve gateway muhasebesi
yazıldı ve gerçek LAN cihazlarıyla doğrulandı.
Ürün bugün gerçekten çalışıyor: blocklist'leri indiriyor, derliyor ve uyguluyor;
Türkiye'nin ulusal tehdit beslemesini kendi API'sinden senkronluyor; bilinmeyen
alan adlarını araştırıp sana "engelleyeyim mi?" diye soruyor; hepsini girişli bir
panelden canlı gösteriyor.

**Commit'ler:**

| Commit | Kapsam |
|---|---|
| `cb2c9a6` | Faz 0 — iskelet: resolver, store, API, panel, paketleme |
| `a8337bc` | Faz 1 — filtreleme, feed'ler, sorgu logu, istemciler, auth, canlı panel |
| `9af0a6b` | Faz 2 — tehdit istihbaratı, ulusal besleme, "engelleyeyim mi?" |
| `2099e72` | Gece raporu |
| `ba2aba5` | SGB sayfalama düzeltmesi (1-tabanlı) |
| _(bu oturumun son commit'i)_ | Faz 3 — cihaz kimliği, aktivite, gateway muhasebesi |

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

### Faz 3 — Cihaz kimliği ve gateway (kısmen)

- **`internal/enforce`:** nftables kural üretimi saf fonksiyon olarak yazıldı, bu
  yüzden kernel ve root olmadan test edilebiliyor. MAC bilindiğinde MAC ile
  engelliyor (cihaz lease yenileyince kaçamasın), yoksa adresle; her iki yönde;
  yamalama yerine istenen duruma **reconcile** ediyor. DNS-only modda açıkça
  "uygulanamaz" diyor ve panele ne olduğunu doğru anlatıyor.
- **`internal/traffic` (dwell):** DNS-only modda sorgu kümelemeyle
  oturum/sitede-süre çıkarımı. Public suffix listesi kullanıyor (naif "son iki
  etiket" kuralı `co.uk`'u site sanır). Her sayı **tahmini** olarak işaretli ve
  sınırları (cache aktiviteyi gizler, süre bir alt sınırdır, bant genişliği
  DNS'ten çıkarılamaz) veriyle birlikte dönüyor.
- **`internal/oui` + `internal/neigh`:** IEEE kayıtlarının tamamı gömülü (39.922
  atama, 338 KB sıkıştırılmış, ikili aramalı). MAC'ler kernel'in komşu
  tablosundan okunuyor — **root gerekmiyor ve trafiğin düğümden geçmesi
  gerekmiyor**, yani DNS-only modda da çalışıyor. Rastgeleleştirilmiş adresler
  (locally-administered bit) hiçbir üreticiye atfedilmiyor ve panelde "kalıcı
  tanıtıcı değil" diye işaretleniyor.
- **`internal/traffic` (sayaçlar):** gateway modu için nftables sayaç kuralları.
  eBPF yerine nftables: her kernel'de var, hedefte derleyici/BTF istemiyor.
  Sayaç zinciri `policy accept` ve içinde hiç `drop` yok — grafik çizmek için
  ağı düşürmek olmaz. Sayaç sıfırlanması negatif hız değil "yeniden başladı"
  olarak ele alınıyor.
- **Panel:** cihaz satırında MAC + üretici, tıklayınca son 24 saatin site bazlı
  aktivitesi ve **"estimated from DNS" / "measured"** rozeti.

### Faz 4 — HA ve iş sürekliliği

- **`internal/backup`:** tek bir arşiv üç işe birden yarıyor — operatörün yedeği,
  replica'ya giden replikasyon yükü, ve self-update öncesi anlık görüntü. Geri
  yükleme **tek transaction**: yarım uygulanmış bir yedek, hiç var olmamış bir
  duruma yol açardı. Sırlar (parola hash'leri, TOTP, API anahtarları) isteğe
  bağlı ve manifest'te açıkça işaretli. Sorgu logu **bilerek** dahil değil: iki
  düğüm aynı ağın farklı yarısını görmüştür.
- **`internal/cluster`:** Raft **yok** — iki düğümlü bir Raft'ın quorum'u yoktur,
  biri ölünce hayatta kalan salt-okunur olur; bu, DNS'i ölmüş bir evin istediğinin
  tam tersi. Bunun yerine primary/replica, tam anlık görüntü replikasyonu ve
  kaçırılan üç heartbeat sonrası kendini yükselten replica. Anlık görüntü paylaşılan
  token'la **HMAC imzalı**: porta erişebilen biri aksi halde filtrelemeyi kapatan
  bir config yükleyebilirdi.
- **`internal/continuity`:** systemd watchdog yalnız düğüm **kendi dinleyicisinden
  bir sorguyu yanıtlayabildiğinde** besleniyor. Süreç canlı ama dilsiz olabilir;
  process-liveness bunu göremez. Ayrıca keepalived config üretimi: sağlık script'i
  gerçekten isim çözüyor, `nopreempt` var (iyileşen düğüm servisi ikinci kez
  kesmesin), ve unicast VRRP (tüketici switch'leri multicast'i düşürüyor).

### Faz 5 — WireGuard ve tünel

- **`internal/vpn`:** curve25519 anahtar üretimi (clamping dahil — onsuz el
  sıkışma iki tarafın da üretemediği bir paylaşılan sır çıkarır), havuzdan sıralı
  adres tahsisi (silinen adres yeniden kullanılıyor), istemci config + QR.
  **Özel anahtar cihaz başına üretilip bir kez veriliyor ve düğümde hiç
  saklanmıyor**: her cihazın özel anahtarını tutan bir sunucu, tek bir hırsızlıkla
  hepsini taklit edebilir hale gelir. `DNS = <düğümün tünel adresi>` satırı
  özelliğin tamamı: o olmadan tünel trafiği taşır ama hiçbir şeyi filtrelemez.
- **`internal/tunnel`:** panele dışarıdan erişmenin üç yolu, **her birinin neyi
  verdiği yazılı** olarak sunuluyor — WireGuard (hiçbir şey açılmıyor, önerilen),
  Cloudflare Tunnel (port yok ama TLS'i Cloudflare sonlandırır), port yönlendirme
  (doğrudan, ama panel internete açılır). Egress profillerinde **kill-switch
  zorunlu**: tünel düşünce policy route sıradan varsayılan rotaya düşer ve trafik
  tam da kaçınılmak istenen yerden, kullanıcının kendi hattından çıkardı.

### Faz 6 — Bildirimler, denetim ve güncelleme

- **`internal/notify`:** e-posta, webhook, ntfy, Telegram, Discord. Zor kısım
  teslimat değil, **kendini tutmak**: her alarmın bir anahtarı var, aynı anahtar
  soğuma süresi içinde tekrar gönderilmiyor, ve her hedefin kendi severity eşiği
  var. Dakikada bir gelen alarm susturulur, sonra önemli olan susturulmuş kanala
  düşer. Sırlar panele geri okunmuyor.
- **`internal/audit`:** kim ne zaman ne değiştirdi. Rakip ürünlerin hiçbirinde
  yok. Okumalar kaydedilmiyor — her panel yenilemesini loglayan bir iz, önemli
  on iki kaydı yüz bin gereksiz kaydın altına gömer.
- **`internal/update`:** arşiv **açılmadan önce** imzalı checksum dosyasına karşı
  doğrulanıyor (TLS bir indirmenin içeriği hakkında hiçbir şey söylemez; ele
  geçirilmiş bir ayna da geçerli TLS sunar). Eski binary saklanıyor, yenisi
  başlayıp config'ini doğrulayana kadar atılmıyor.
- **`internal/metrics`:** Prometheus ucu — operatörün grafiğe dökeceği sayılar,
  sürecin sahip olduğu her sayaç değil.

---

## Ölçülen sayılar

| | |
|---|---|
| Derlenen kural | 599.154 (3 feed) — ~6 MB, 594 ms |
| Filtre eşleşmesi | 310 ns (100K kuralda, hit) / 212 ns (miss) |
| SGB beslemesi | 464.435 domain + 15.191 IP; ilk tam senkron 37 dk sürdü, ruleset 1.060.458 kurala / ~10,6 MB çıktı |
| SSE akışı | 5 saniyede 14 kare / 26 kayıt (sorgu başına mesaj değil) |
| Cihaz tanıma | 3 gerçek LAN cihazı doğru üreticiyle çözüldü (Intel, Espressif, TP-Link) |
| Panel bundle | 276 KB / 93 KB gzip |
| Binary | ~16 MB, statik, stripped; amd64 + arm64 + armv7 |
| Yedek/geri yükleme | canlı: 1293 baytlık arşiv, boş düğüme geri yüklendi, kural gerçekten engelledi |
| Test | 23 paket, `-race` temiz |

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
7. **SGB sayfalamasında off-by-one.** API 1-tabanlı: `page=0` ile `page=1` aynı
   veriyi dönüyor ve son sayfa `pageCount` numaralı. `0..pageCount-1` yürüyüşü ilk
   sayfayı iki kez çekip **son sayfayı hiç çekmiyordu** — ilk tam senkron 464.435
   yerine tam 464.000 kayıt getirdi, en eski 435 kayıt eksik kaldı. Testler bunu
   kaçırmıştı çünkü sahte API'yi 0-tabanlı yazmıştım; fixture gerçek API gibi
   düzeltildi, yürüyüş `1..pageCount` yapıldı ve canlı API'ye karşı doğrulandı
   (IP tipi: 1..16 sayfa = tam 15.191 kayıt).

Bir de yanlış alarm: export dosyasında 9.000 kadar "yinelenen" satır göründü, ama
bu `sort -u`'nun locale karşılaştırması yüzündendi. `LC_ALL=C` ile sayı 463.960 —
veritabanıyla birebir. Yineleme yok.

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
- **nftables enforcement'ı ve bant genişliği sayaçları** yalnız kural üretimi ve
  çıktı ayrıştırma seviyesinde test edildi; gerçek bir gateway kurulumunda hiç
  uygulanmadı. Sayaç okuma yolu (`nft -j`) gerçek çıktıya karşı değil, sabit
  fixture'lara karşı doğrulandı.
- **VRRP/keepalived** yalnız config üretimi seviyesinde test edildi; gerçek bir
  çift düğümde hiç çalıştırılmadı, devralma süresi ölçülmedi.
- **Cluster replikasyonu** sahte eşlere karşı test edildi (imza reddi, promotion,
  eşitlik-bozucu dahil); iki gerçek düğüm arasında hiç çalıştırılmadı.
- **systemd watchdog** sahte bir notify soketine karşı doğrulandı; gerçek systemd
  altında `Type=notify` ile hiç başlatılmadı.
- **WireGuard kernel entegrasyonu** hiç çalıştırılamadı: bu makinede modül yüklü
  değil ve root yok. Anahtar üretimi, adres tahsisi, config/QR üretimi ve peer
  yaşam döngüsü test edildi; `wgctrl` ile gerçek arayüz programlama edilmedi.
- **Cloudflare Tunnel** yalnız config üretimi ve `cloudflared` varlık tespiti
  seviyesinde; gerçek bir tünel hiç kurulmadı.
- **Egress profilleri** yalnız script üretimi olarak test edildi; gerçek policy
  routing hiç uygulanmadı.
- **Gerçek bir sürümün indirilip kurulması** denenmedi: doğrulama, kurulum,
  geri alma ve sağlık kapısı üretilmiş anahtarlar ve geçici dosyalarla test
  edildi; GitHub'dan gerçek bir artefakt çekilmedi.
- **SMTP teslimatı** gerçek bir sunucuya karşı denenmedi (webhook denendi).
- **conntrack canlı bağlantılar** hiç yazılmadı: bu makinede modül yüklü değil
  (`/proc/net/nf_conntrack` yok).
- **IPv6 komşu tablosu** okunmuyor; `/proc/net/arp` yalnız IPv4. IPv6-only bir
  istemcinin MAC'i boş kalır.
- **Saatlik query-log rollup'ının** kendi testi yok.
- **Panelin görsel render'ı** doğrulanamadı (tarayıcı paneli kompozit etmiyor);
  veri akışı JS ile ölçülerek doğrulandı.

### Panel — Faz 4-6 ekranları

Bilgi mimarisi: günlük kullanılanlar üst seviyede (Dashboard, Review, Devices,
Tunnel, Blocklists, Your rules), yılda bir dokunulanlar tek bir **System**
sayfasında alt sekmelerle (Cluster · Backup · Alerts · Audit · Updates). Yedi
ayrı üst sekme, günlük ekranları kenara iterdi.

- **Tunnel:** cihaz ekleme tek bir ana üstüne kurulu — özel anahtarın var olduğu
  tek an. QR + config **bir kez** gösteriliyor ve bunu açıkça yazıyor. Peer
  kartlarında el sıkışma zamanı, transfer, aç/kapat. Altta panele dışarıdan
  erişim seçenekleri, her birinin neyi verdiği yazılı.
- **System → Cluster:** tek düğümde "kendi başına çalışıyor" boş durumu; çiftte
  primary erişilemezse uyarı, eş kartları, revizyon ve "replica'ya in" düğmesi.
- **System → Backup:** indir (sırlı/sırsız, sırlı olanın ne içerdiği yazılı),
  geri yükle **önce kuru çalıştırma** — arşivin içindekiler gösterilip onay
  isteniyor.
- **System → Alerts:** kanal kartları, tür seçince alanların değiştiği ekleme
  formu, test düğmesi (hata mesajını gösteriyor — testin faydalı kısmı o).
- **System → Audit:** gün filtreli tablo, başarısızlar kırmızı noktayla.
- **System → Updates:** sürüm kartı ve güncellemenin nasıl uygulandığını anlatan
  üç adım.

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
