import type { Dictionary } from "./en";

/**
 * Kept as a full, separately-typed mirror of the English dictionary rather
 * than a partial override: a Turkish string that quietly falls back to
 * English is worse than a build failure that says exactly which key is
 * missing.
 */
export const tr: Dictionary = {
  common: {
    loading: "Yükleniyor…",
    signOut: "çıkış yap",
  },

  nav: {
    dashboard: "Panel",
    review: "İnceleme",
    devices: "Cihazlar",
    tunnel: "Tünel",
    blocklists: "Engel listeleri",
    rules: "Kurallarınız",
    system: "Sistem",
  },

  dashboard: {
    queries: "Sorgular",
    sinceStart: "başlangıçtan beri",
    blocked: "Engellenen",
    queriesUnit: "{count} sorgu",
    rulesLoaded: "Yüklü kural",
    listsUnit: "{count} liste",
    bandwidth: "Bant genişliği",
    perClientCounters: "cihaz başına bayt sayacı",
    gatewayOnly: "Ağ geçidi modu gerekir",
    resolver: "Çözümleyici",
    serving: "çalışıyor",
    down: "kapalı",
    cacheHits: "Önbellek isabeti",
    answeredWithoutUpstream: "üst sunucuya gitmeden yanıtlandı",
    uptime: "Çalışma süresi",
    avgLatency: "ortalama {ms} ms",
    droppedLog:
      "Disk yetişemediği için {count} log kaydı düştü. Sorgu günlüğü saklama süresini kısaltın ya da yalnızca RAM'de tutmaya geçin.",
  },

  footer: {
    license: "Apache License 2.0",
    source: "Kaynak kod",
  },

  language: {
    label: "Dil",
    en: "English",
    tr: "Türkçe",
  },

  suggestions: {
    mode: {
      title: "Mod",
      transparentTitle: "Şeffaf Mod",
      transparentDescription:
        "Yalnızca izler ve kaydeder. Hiçbir şeyi otomatik engellemez.",
      defenseTitle: "Defans Mod",
      defenseDescription:
        "Araştırır ve bildirir; geçerli SSL sertifikası olan bir alan adını asla otomatik engellemez.",
    },
    sourcesPartialPrefix:
      "{total} tehdit kaynağından yalnızca {active} tanesi aktif.",
    sourcesPartialSuffix:
      "kullanılmadan önce ücretsiz bir API anahtarı istiyor.",
    loading: "Yükleniyor…",
    emptyTitle: "İncelenecek bir şey yok.",
    emptyDetail:
      "Ağınızın çözdüğü isimler arka planda tehdit kaynaklarına karşı kontrol ediliyor. İkinci bir göze değer bir şey olursa burada görünecek.",
    queries: "{count} sorgu",
    askedBy: "sorgulayan: {clients}",
    firstSeen: "ilk görülme {when}",
    check: "incele",
    block: "Engelle",
    allow: "İzin ver",
    ignore: "Yoksay",
    officialSource: "resmi kaynak",
    reputable: "raporlandı · size kalmış",
    malicious: "zararlı",
    suspect: "şüpheli",
    tls: {
      unchecked: "SSL kontrol edilmedi",
      valid: "geçerli SSL",
      certInvalid: "geçersiz sertifika",
      hostnameMismatch: "sertifika uyuşmuyor",
      noResponse: "web sunucusu yanıt vermiyor",
    },
    age: {
      unknown: "yaş bilinmiyor",
      years: "{years} yıllık domain",
      days: "{days} gün önce kaydedildi",
      highRisk: "yeni ve doğrulanmamış · ",
    },
  },

  ownedDomains: {
    title: "Benim Sitelerim",
    description:
      "Kendi barındırdığınız alan adları. Buraya eklenen bir isim asla bu listeye düşmez — ne görünür ne de otomatik engellenir.",
    loading: "Yükleniyor…",
    empty: "Henüz eklenmiş bir alan adı yok.",
    remove: "kaldır",
    domainLabel: "Alan adı",
    domainPlaceholder: "benimsitem.com",
    labelLabel: "Etiket (opsiyonel)",
    labelPlaceholder: "ev sunucusu",
    add: "Ekle",
  },
};
