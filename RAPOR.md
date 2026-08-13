# SedDNS — Geliştirme Raporu

**Tarih:** 13 Ağustos 2026
**Depo:** [github.com/MmTKya/DNS](https://github.com/MmTKya/DNS) — public
**Çalışan sürüm:** v0.12.0, Raspberry Pi 5 üzerinde Ubuntu Server 26.04

---

## Özet

Şartnamedeki altı faz yazıldı, **ve artık gerçek donanımda çalışıyor.** Bir
önceki rapor "hiçbiri gerçek donanımda çalışmadı" diyordu; bu artık doğru
değil ve aradaki fark raporun en değerli kısmı: kurulum on bir sürüm sürdü ve
yolda **yedi gerçek hata** çıkardı — hiçbiri testlerde görünmeyen, sadece
gerçek bir makinede ortaya çıkan türden.

Düğüm şu anda evin ağında duruyor: 759.300 kural, altı kaynak, 53 MB bellek,
iki saattir kesintisiz. Kendini panelden güncelleyebiliyor, imzayı doğruluyor,
başarısız olursa geri alıyor.

## Sürüm geçmişi

| Sürüm | Ne getirdi |
|---|---|
| `v0.1.0` | İlk yayın — altı fazın tamamı |
| `v0.1.1` | İlk kurulumda çıkan üç hata |
| `v0.2.0` | Hesap ekranı, manuel blocklist kaynağı, ölü feed'lerin değişimi |
| `v0.2.1` | Panelden güncelleme (imzalı, geri alınabilir) |
| `v0.2.2` | Panel güncelleme sonrası düğümün dönüşünü kendisi bekliyor |
| `v0.2.3` | Kural eylemleri (block/allow/rewrite), okunabilir sürüm notları |
| `v0.2.4` | Sürüm notu hattının onarımı |
| `v0.2.5` | Ayrıcalık ayrımı — düğüm kendi binary'sini yazamaz |
| `v0.2.6` | Atlanan sürümlerin notları da gösteriliyor |
| `v0.3.0` | Kendi DNS sunucunu seçme; cluster'ın config'e bağlanması |
| `v0.3.1` | İkinci düğüm eşleştirme ekranı |
| `v0.3.2` | Resolver ölçümü — doğruluk hızdan önce |
| `v0.4.0` | SERVFAIL kurtarma, Quad9 kaldırıldı, rebinding koruması, giriş hız sınırı |
| `v0.4.1` | Dashboard'da upstream gecikmeleri ve kurtarma sayacı |
| `v0.5.0` | **SedDNS adı**, logo, System → Logs (journalctl'e gerek yok) |
| `v0.6.x` | Tam göç: servis, binary, dizinler `seddns` |
| `v0.7.0` | Engellenen site kendini açıklıyor (sebep + opsiyonel izin ver) |
| `v0.8.x` | Cihazlar isimleriyle görünüyor (mDNS + router + üretici) |
| `v0.9.0` | Dashboard açılışta dolu geliyor |
| `v0.10.0` | Açılıştaki 10 sn korumasızlık kapandı; kurtarma önbelleği |
| `v0.11.0` | Uzaktan erişim + Cloudflare Tunnel ekranı, tehdit kaynağı anahtarları |
| `v0.12.0` | **İkinci güvenlik taraması:** 6 stdlib açığı, engelleme sayfasında CSRF, güvenlik başlıkları |

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

### Panel

Yedi üst sekme: Dashboard · Review · Devices · Tunnel · Blocklists · Your rules
· System. Günlük kullanılanlar üstte; yılda bir dokunulanlar tek bir **System**
sayfasında alt sekmelerle (Resolvers · Cluster · Backup · Alerts · Audit ·
Updates). Kendi parolan ve iki faktör başlıktaki adının altında — insanlar
orada arar.

Sonradan eklenenler: **hesap ekranı** (parola + TOTP, parola değişiminin tüm
oturumları düşürdüğünü önceden söyleyerek), **manuel blocklist kaynağı**,
**kural besteci** (block / allow / rewrite / NXDOMAIN, ürettiği sözdizimini
göstererek), **resolver seçimi**, **güncelleme düğmesi** (notlar düğmenin
üstünde) ve **cluster eşleştirme rehberi**.

---

## Gerçek donanımda bulunan hatalar

Bu bölüm yeni. Hepsi ilk kurulumda ya da sonrasında canlı makinede çıktı;
hiçbiri birim testlerinde görünmüyordu.

1. **Tek satırlık kurulum hiçbir zaman soru soramıyordu.** `curl | bash`
   altında stdin script'in kendisi, yani onay okunacak terminal yok. Installer
   durup `--unattended` öneriyordu — root çalışan bir script için öğretilecek
   en yanlış alışkanlık. `/dev/tty`'den okuyor artık.

2. **Port 53'ü boşaltmak makinenin DNS'ini de götürüyordu.** Ubuntu'da
   `/etc/resolv.conf`, kapatılan stub'ı gösteren bir symlink. Kurulum başarılı
   görünüyor, apt çalışmıyor ve **hiçbir blocklist inmiyor**.

3. **systemd yeniden başlatma sınırı hiç devrede değildi** — `[Service]`
   bölümüne yazılmıştı, systemd `[Unit]` bekliyor ve sessizce yok sayıyor.

4. **HaGeZi listelerinin deposu yok olmuş.** Birincil URL'ler 404, sadece bir
   CDN önbelleği hayatta tutuyordu. `doubleclick.net` bu yüzden geçiyordu.
   Koruma sessizce düşmüştü ve hiçbir şey haber vermiyordu.

5. **Panelden güncelleme "read-only file system" ile düşüyordu.** Sebep
   sertleştirmenin doğru çalışmasıydı: düğüm kendi binary'sini yazamıyor.
   Kolay çözüm o yetkiyi vermekti — ağa açık bir sürecin bir dahaki açılışta
   çalışacak programı yeniden yazabilmesi demek. Bunun yerine iş ikiye
   bölündü.

6. **`changelog: disable` sürüm notu dosyasını da atıyordu** — tam da konusu
   "okunabilir notlar" olan sürüm boş notla yayınlandı.

7. **Varsayılan resolver en yavaş seçenekti.** Düğümden ölçüldü: Quad9 139 ms,
   Google 45 ms, Cloudflare 64 ms. Config'e gömülü bir tahmin, ölçülebilir bir
   ayara dönüştü.

Bunlara ek olarak, geliştirme sırasında testlerin yakaladığı hatalar önceki
raporda listelenmişti ve hâlâ geçerli: `.gitignore`'un `main.go`'yu yok
sayması, feed küçülme korumasının geç çalışması, SGB sayfalama kayması, rAF'in
gizli sekmede tetiklenmemesi, cluster tie-break'inin geçici hatada kaybolması,
yedek testlerinin gzip içinde düz metin araması, `vpn.Available()`'ın yanlış
şeyi kontrol etmesi.

---

## Ölçülen sayılar

Hepsi çalışan düğümden, tahmin değil.

| | |
|---|---|
| Derlenen kural | 759.300, altı kaynak |
| Bellek | 82 MB |
| Soğuk sorgu | 74,8 ms ortalama (LAN'dan) |
| Önbellekten | 4 ms |
| Yük | 200 paralel sorgu 1,4 saniyede, düğüm sağlıklı |
| Ruleset derleme | ~10 saniye (yeniden başlatmada) |
| Binary | ~24 MB, statik; amd64 + arm64 + armv7 |
| Panel | 332 KB / 105 KB gzip |
| Kod | 18.452 satır Go + 8.597 satır test |
| Test | 24 paket, `-race` temiz |
| Güncelleme | panelden 0.2.1 → 0.2.6, imza doğrulandı, kesinti ~2 sn |

---

## Doğrulanmayanlar — dürüst liste

Önceki listenin çoğu kapandı. Kalanlar:

- **İki düğümlü replikasyon gerçek donanımda hiç çalışmadı.** Kod, testleri ve
  config doğrulaması var; "primary düştü, replica devraldı" canlı görülmedi.
- **VRRP / keepalived** aynı şekilde: üretilen konfigürasyon test edildi,
  gerçek bir devralma ölçülmedi.
- **WireGuard tüneli** kurulmadı. QR ve config üretimi doğrulandı, gerçek bir
  telefon bağlanmadı.
- **Gateway modu** — nftables kuralları, per-client bant genişliği, conntrack.
  Gerçek bir gateway makinesi gerekiyor.
- **Tehdit kaynağı anahtarları hâlâ girilmedi.** Panelde ekranı artık var
  (System → Threat sources); anahtarlar alınıp girilmedi, dolayısıyla öneri
  akışı gerçek yanıtlarla çalışmadı.
- **Cloudflare Tunnel ekranı gerçek bir tünelle denenmedi.** Yapılandırma
  üretiliyor ve dosyaya yazılıyor; `cloudflared` kurulup çalıştırılmadı.
- **Rebinding koruması gerçek bir saldırıya karşı denenmedi.** Testleri var ve
  yerel adları bozmadığı doğrulandı; kasıtlı bir rebinding denemesi yapılmadı.
- **Panel LAN'da düz HTTP** — oturum çerezi ağda açık geçiyor.
- **Sorgu logu saatlik rollup'ının** kendi testi yok.
- **Panelin görsel render'ı** doğrudan doğrulanamıyor (tarayıcı paneli
  kompozit etmiyor); veri akışı ve DOM ile doğrulanıyor.


---

## Gece çalışması — 13 Ağustos, sabah raporu

Üç iş vardı: çözümleme hiç kırılmasın, Quad9 gitsin, güvenlik taraması. Üçü de
bitti ve **v0.4.0** olarak yayınlandı; Pi'de kurulu ve çalışıyor.

### 1. Açılmayan sayfa sorunu — çözüldü

Kök sebep tek bir davranıştı: bir upstream **SERVFAIL** döndürdüğünde düğüm o
cevabı olduğu gibi istemciye geçiriyordu. SERVFAIL "bu ad yok" demek değil,
"öğrenemedim" demek — ve genellikle o resolver'a özgü bir sorun.

`gib.gov.tr` bunun canlı örneğiydi: Quad9 üzerinden SERVFAIL, Google ve
Cloudflare üzerinden sorunsuz. Ev bu düğüme bağlansaydı bazı devlet siteleri
hiç açılmayacak, hiçbir yerde de sebebi yazmayacaktı.

Artık SERVFAIL gelince düğüm **farklı bir resolver'a bir kez daha soruyor**.
NXDOMAIN'e dokunmuyor — o geçerli bir cevap, ve yeniden sormak hem her yazım
hatasını yavaşlatır hem de bu düğümün engellemeye karar verdiği bir ada ikinci
şans verirdi.

**Doğrulama:** aynı Pi, hâlâ Quad9 yapılandırmasıyla, `gib.gov.tr` artık gerçek
IP'leriyle dönüyor. Ardından **30 gerçek alan adı** tarandı — Türk bankaları,
devlet, e-ticaret, operatörler, global servisler — **sıfır sorun**.

### 2. Quad9 varsayılanlardan çıkarıldı

Gerçek hattan ölçüldüğünde adayların en yavaşıydı (139 ms / Google 45 ms) ve
`gib.gov.tr`'yi hiç çözemiyordu. Yeni kurulumlar **Cloudflare + Google** ile
geliyor. Ölçüm ekranının aday listesinden de çıkarıldı.

Mevcut kurulumlar config dosyalarındakini korur — Pi'de hâlâ Quad9 yazılı.
**System → Resolvers → Measure → Use the best two** ile değiştirebilirsin;
kurtarma mekanizması bu arada açığı kapatıyor.

### 3. Güvenlik taraması

Elimde "siberai" diye bir araç yok; bunun yerine gerçek ve doğrulanabilir
olanları çalıştırdım.

| Araç | Sonuç |
|---|---|
| `govulncheck` (resmî Go açık veritabanı) | Kodumuzun çağırdığı **0 açık** |
| `npm audit` (panel) | **0 açık** |
| `gosec` (statik analiz) | 32 bulgu — hepsi okundu, bastırılmadı |

**Bulunan ve kapatılan iki gerçek açık:**

**Girişte hız sınırı yoktu.** Parola doğrulama argon2id ile bilerek pahalı: her
deneme **19 MiB** ve gerçek CPU. Kimlik doğrulaması gerektirmeden ve sınırsız
bırakıldığında bu, LAN'dan **resolver'ı belleksiz bırakmanın** bir yoluydu —
hiç giriş yapmadan evin DNS'ini durdurabilirdin. Artık adres başına dakikada 10
deneme, aynı anda en fazla 4 doğrulama, ve meşru girişler reddedilmek yerine
sıraya giriyor. Canlıda doğrulandı: 8 başarısız denemeden sonra `429`.

**DNS rebinding koruması yoktu.** İnternetteki bir sayfa, sahibi olduğu bir ad
için `192.168.1.1` cevabı aldırıp tarayıcıyı senin router'ınla konuşturabilir.
Artık genel bir adın iç ağ adresine çözülmesi engelleniyor. Muafiyetler daha
önemli yarısı: `.local`, `.lan`, `.home.arpa`, tek kelimelik adlar ve ters
sorgular hiç ellenmiyor, düğümün kendi engelleme cevapları da öyle — NAS'ın,
yazıcın, router'ın adı çalışmaya devam eder.

**gosec'in kalan 30 bulgusu değerlendirildi:** üçü gerçek tamsayı dönüşüm
hatasıydı ve düzeltildi (saat geri giderse ortalama gecikmeyi bozan sayaç,
65535'ten fazla listede kaynak etiketini kaydıran indeks, veritabanından gelen
kayıt tipi). Kalanlar yanlış pozitif ve gerekçeleriyle elendi: CI bayrağından
gelen dosya yolları, kriptografik olması gerekmeyen bir sapma rastgelesi, ve
kod içinde sabit tanımlı tablo adlarından kurulan SQL. Hiçbiri `#nosec` ile
susturulmadı.

### Gece bulunan ve raporlanan sınırlamalar

- **Panel LAN'da düz HTTP.** Oturum çerezi ağda açık geçiyor. Aynı ağdaki biri
  onu okuyabilir. Çözümü sertifika ya da paneli WireGuard arkasına almak.
- **Yeniden başlatmadan sonra ~10 saniye filtreleme yok** (önceki raporda da
  vardı, hâlâ geçerli).

### Sabah için önerim

1. Paneli aç, **System → Resolvers → Measure** → **Use the best two**
2. `gib.gov.tr` ve birkaç sitede gez, bir sorun var mı gör
3. Sorun yoksa router'ın DHCP'sinde DNS'i `192.168.68.84` yap, ikincil
   `192.168.71.53`
4. Bir şey açılmazsa: **System → Audit** ve `journalctl -u seddns | grep
   "dropped an answer"` — rebinding koruması bir şeyi yanlışlıkla düşürdüyse
   orada görünür, ve config'de `dns.rebind_protection: false` ile tek satırda
   kapatılır

Düğüm şu an: **v0.4.0**, 759.311 kural, 82 MB, 2 saat 51 dakikadır ayakta.


---

## İkinci güvenlik taraması — 14 Ağustos gecesi

İlk taramadan sonra yedi sürüm ve altı yeni paket eklendi; hiçbiri incelenmemişti.

### Kapatılan açıklar

**Go standart kütüphanesinde altı açık, hepsi bu koddan erişilebilir.** İkisi
paneli ve engelleme sayfasını sunan HTTP sunucusunda, biri engelleme
sayfasının saldırgan kontrolündeki `Host` başlığını render ettiği şablon
motorunda, üçü TLS, URL ve sertifika ayrıştırmada. Araç zinciri 1.26.6'ya
yükseltildi; `go.mod` da o sürümü istiyor, dolayısıyla CI otomatik takip
ediyor. Tarama artık **sıfır** diyor.

**Engelleme sayfasının "izin ver" düğmesinde CSRF.** Serbest bırakılacak alan
adı **form gövdesinden** geliyordu — yani internetteki herhangi bir sayfa,
ziyaretçisinin tarayıcısına senin düğümüne POST attırıp istediği adı
engellemeden çıkarabilirdi. Bu açığı, özelliği eklerken ben açtım.

Artık ad yalnızca `Host` başlığından alınıyor; başka bir sitedeki form onu
ayarlayamaz. Ayrıca yabancı `Origin` taşıyan istek reddediliyor ve zaten
engellenmemiş bir ad serbest bırakılamıyor. Üç test yazıldı, biri doğrudan
saldırının kendisi.

Yalnızca `allow_release` açıkken geçerliydi, o da varsayılan kapalı.

**Panelde hiç güvenlik başlığı yoktu.** Evdeki her ismi yönlendirebilen bir
kutuya tarayıcıya "beni çerçeveleme" ve "script'ler yalnızca buradan" demeyi
bırakmak fazlaydı. CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy` ve
`Permissions-Policy` eklendi — ve politika çalışan panele karşı doğrulandı:
satır içi script yok, tüm varlıklar aynı kaynaktan, yani hiçbir şeyi bozmuyor.

### Bakılan ve gerekçesiyle bırakılanlar

- **Panel CSRF'i zaten kapalı:** oturum çerezi `SameSite=Lax` ve durum
  değiştiren tek bir `GET` yok. Doğrulandı.
- **Kullanıcı adı sızdırma yok:** olmayan kullanıcı ile yanlış parola aynı
  cevabı veriyor. Canlıda test edildi.
- **`/api/metrics` kimlik doğrulamasız** ama yalnızca toplam sayaçlar
  veriyor — alan adı ya da istemci adresi yok. Prometheus'un işi bu.
- **`gosec`'in 32 bulgusundan yeni paketlerde olan ikisi** incelendi: biri bir
  ayar anahtarının adında "credentials" geçmesi, diğeri dosya izniydi ve
  sıkıştırıldı. Kalanı önceki taramada gerekçelendirilmişti.
- **Bağımlılıklarda yeni sürümler var ama bilinen açık yok.** Çalışan bir ev
  DNS'inin altında kırk dokuz bağımlılığı gece yarısı güncellemek,
  düzeltilecek riskten farklı bir risk üretir.

### Hâlâ açık olan tek şey

**Panel LAN'da düz HTTP.** Oturum çerezi ağda açık geçiyor. Bilinçli olarak
bırakıldı: kendinden imzalı sertifika kullanıcıya "uyarıyı geç" refleksi
kazandırır, ve saldırganın zaten WiFi parolasına sahip olması gerekir.
**Paneli internete açarsan bu derhal değişir** — o durumda WireGuard şart.

---

## Sıradaki adımlar

1. **İkinci düğümü kur ve devralmayı ölç.** Listedeki en büyük boşluk bu.
2. **Panele uzaktan erişim ayarları** ve **Cloudflare Tunnel** — ikisi de şu an
   sadece bilgi metni.
3. **Tehdit kaynağı anahtarları için ayarlar ekranı** — şimdilik
   `POST /api/intel/settings`.
4. **Derleme boşluğunu kapat**: ruleset derlenene kadar sorguları bekletmek ya
   da önceki ruleset'i elde tutmak.
5. **Router'da DHCP'yi düğüme çevir** ve evin tamamını gerçek kullanımda izle.
