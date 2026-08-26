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

  clients: {
    pauseWarning:
      "Yalnızca-DNS modunda bir cihazı duraklatmak, onun bu node üzerinden isim çözmesini durdurur. Ağ erişimi elinde kalır.",
    gatewayEnforceable: "Ağ geçidi modu bunu uygulanabilir kılar.",
    device: "Cihaz",
    queries: "Sorgular",
    lastSeen: "Son görülme",
    filtering: "Filtreleme",
    paused: "Duraklatıldı",
    none: "Henüz sorgu yapan bir cihaz yok.",
    randomisedMac: "rastgeleleştirilmiş — kararlı bir kimlik değil",
    activity: {
      last24h: "Son 24 saat",
      measured: "ölçüldü",
      estimated: "DNS'ten tahmin edildi",
      none: "Bu cihaz için henüz bir kayıt yok.",
      visit: "ziyaret",
      visits: "ziyaret",
    },
  },

  feeds: {
    refreshing: "Yenileniyor…",
    refreshNow: "Şimdi yenile",
    aggressive: "agresif şekilde engeller",
    nonCommercial: "ticari olmayan lisans",
    notInCatalog:
      "Artık katalogda yok. Burada saklanan URL'den çalışmaya devam ediyor, ama o girişi artık kimse bakımını yapmıyor — hâlâ güncellendiğini kontrol edin ya da kaldırın.",
    rulesCount: "{count} kural",
    updated: "güncellendi {when}",
    fillingNow: "Şimdi doluyor.",
    remove: "kaldır",
    addSource: "+ Kaynak ekle",
    name: "İsim",
    namePlaceholder: "Listem",
    url: "URL",
    add: "Ekle",
    cancel: "vazgeç",
    addHelp:
      "Hem hosts dosyaları hem de Adblock sözdizimli listeler çalışır; biçim içerikten tespit edilir. Kaynak eklendiği anda indirilip derlenir",
    addHelpFiledPrefix: "ve şu şekilde kaydedilir:",
  },

  rules: {
    none: "Henüz kendi kuralınız yok.",
    remove: "kaldır",
    addRule: "Kural ekle",
    useForm: "formu kullan",
    writeSyntax: "sözdizimini kendim yazayım",
    ruleLabel: "Kural",
    domainLabel: "Alan adı",
    answerWith: "Şu adresle yanıtla",
    note: "Not (opsiyonel)",
    notePlaceholder: "neden eklediğiniz",
    important:
      "izin kurallarını da geçersiz kılsın — bir şey ısrarla geçiyorsa kullanın",
    actions: {
      block: "engelle",
      allow: "izin ver",
      rewrite: "yeniden yaz",
      nxdomain: "Yok olduğunu söyle",
    },
    help: {
      block: "İsim, altındaki her şeyle birlikte çözülmeyi durdurur.",
      allow:
        "Bir engel listesinde olsa bile isim çözülür. İzin ver, engelle'yi yener — bir siteyi geri almanın yolu budur.",
      rewrite:
        "İsim, seçtiğiniz bir adresle yanıtlanır — örneğin bir cihazı yerel bir sunucuya yönlendirmek için.",
      nxdomain:
        'İsim, bir adres yerine "yok" diye yanıtlanır. Bazı uygulamalar bunu 0.0.0.0\'dan daha iyi karşılar.',
    },
    describe: {
      scopeAll: "ve altındaki her şey",
      scopeExact: "tam olarak",
      allow: "{scope} her zaman çözülür, tüm engel listelerini yener",
      rewriteNx: '{scope} "yok" diye yanıtlar',
      rewriteTo: "{scope} {address} ile yanıtlar",
      blockImportant: "{scope} engellenir, izin kurallarını geçersiz kılar",
      block: "{scope} engellenir",
      onlyQtype: "yalnızca {qtypes} sorguları",
      onlyClient: "yalnızca {client} için",
    },
  },

  system: {
    nav: {
      machine: "Makine",
      logs: "Loglar",
      upstreams: "Çözümleyiciler",
      intel: "Tehdit kaynakları",
      gateway: "Ağ geçidi modu",
      cluster: "Cluster",
      backup: "Yedekleme",
      alerts: "Uyarılar",
      audit: "Denetim",
      updates: "Güncellemeler",
    },
    cluster: {
      standaloneTitle: "Bu node tek başına çalışıyor.",
      standaloneDetail:
        "İkinci bir node, bu node yeniden başlarken, güncellenirken ya da fişi çekildiğinde evi çözümlemeye devam ettirir — bu node'un yapılandırmasını takip eder ve o sessiz kalırsa devralır. O zamana kadar buradaki her şey boşta durur ve hiçbir maliyeti yoktur.",
      setupSecondNode: "İkinci bir node kur",
      noPrimary:
        "Hiçbir primary'ye ulaşılamıyor. Bu durum kısa sürede değişmezse bu node kendini terfi ettirecek.",
      syncFailed: "Son replikasyon denemesi başarısız oldu: {error}",
      thisNode: "bu node",
      stepDown: "Replica'ya geri çekil",
      revision: "revizyon {rev}",
      seen: "görüldü {when}",
      lastReplicated: "Son replikasyon {when}.",
      showPairing: "eşleştirme yapılandırmasını göster",
    },
    backup: {
      download: "İndir",
      downloadDetail:
        "Ayarlar, engel listesi seçimleri, kendi kurallarınız ve cihazlarınız. Sorgu günlüğü dahil değildir: hem büyük hem de bu ağın ne yaptığının bir kaydıdır, nasıl yapılandırıldığının değil.",
      downloadBackup: "Yedeği indir",
      includeSecrets: "Giriş bilgileri ve API anahtarlarını dahil et",
      secretsWarning:
        "İkinci dosya parola özetlerini, iki faktörlü kimlik doğrulama sırlarını ve tehdit-kaynağı anahtarlarınızı içerir. Node'un kendisi gibi davranın.",
      restore: "Geri yükle",
      restoreDetail:
        "Arşiv önce incelenir, yalnızca onayladığınızda uygulanır. Yapılandırma dosyanız buradan asla üzerine yazılmaz — başka bir node'dan gelen bir arşiv kendi dinleyicilerini taşır ve bunları geri yüklemek bu node'u erişilemez bırakabilir.",
      contains: "Bu arşiv şunları içeriyor:",
      restored: "Geri yüklendi:",
      taken: "alındı {when}",
      includesSecrets: "giriş bilgileri ve anahtarlar dahil",
      replaceSettings: "Bu node'un ayarlarını değiştir",
    },
    alerts: {
      andAbove: "{severity} ve üzeri",
      sendTest: "Test gönder",
      sent: "Gönderildi",
      remove: "kaldır",
      addDestination: "Hedef ekle",
      name: "İsim",
      namePlaceholder: "Telefonum",
      severityLabel: "Şu önem düzeyinde gönder",
      severityInfo: "info ve üzeri — her şey",
      severityWarning: "warning ve üzeri",
      severityCritical: "yalnızca critical",
      add: "Ekle",
      recent: "Son uyarılar",
      none: "Dikkat gerektiren bir şey olmadı.",
      lastDelivered: "son iletim {when}",
      delivered: "{count} gönderildi",
      kinds: {
        smtp: "E-posta",
        ntfy: "ntfy",
        webhook: "Webhook",
        telegram: "Telegram",
        discord: "Discord",
      },
    },
    audit: {
      today: "Bugün",
      thisYear: "Bu yıl",
      daysCount: "{days} gün",
      none: "Bu dönemde bir değişiklik yapılmadı.",
      onlyChanges:
        "Yalnızca değişiklikler kaydedilir. Her panel yenilemesini kaydeden bir günlük, önemli kayıtları gömerdi.",
    },
    updates: {
      running: "Çalışan",
      checking: "Kontrol ediliyor…",
      checkAgain: "Tekrar kontrol et",
      currentRelease: "Bu, güncel sürüm.",
      notManaged:
        "Bu binary güncelleyici tarafından kurulmadı, bu yüzden kendini değiştirmeyecek. Nasıl kurduysanız öyle güncelleyin.",
      howApplied: "Bir güncelleme nasıl uygulanır",
      verifyTitle: "Doğrula.",
      verifyDetail:
        "Arşiv, açılmadan önce imzalı bir sağlama toplamı dosyasına karşı kontrol edilir. Geçerli bir TLS bağlantısı, bir indirmenin içeriği hakkında hiçbir şey söylemez.",
      snapshotTitle: "Anlık görüntü.",
      snapshotDetail:
        "Ayarlarınız önce dışa aktarılır, böylece kötü bir sürüm yas tutulacak bir şey yerine geri alınabilir bir şey olur.",
      swapTitle: "Değiştir ve kanıtla.",
      swapDetail:
        "Yenisi başlayıp yapılandırmasını doğrulamak zorunda olduğu sürece eski binary saklanır. Başaramazsa eskisi geri döner.",
      versionAvailable: "{version} sürümü mevcut.",
      whatChanged: "Neler değişti",
      noNotes: "Bu sürüm not eklenmeden yayınlandı.",
      installConfirm: "{version} kurulup çözümleyici yeniden başlatılsın mı?",
      verifyingInstalling: "Doğrulanıyor ve kuruluyor…",
      yesInstall: "Evet, kur",
      cancel: "vazgeç",
      install: "{version} kur",
      runningVersion: "{version} çalışıyor.",
      verifiedBackUp:
        "Doğrulandı, kuruldu ve tekrar ayakta. Önceki binary şu adla saklanıyor:",
      waitingBack:
        "{version} kuruldu ve doğrulandı. Node'un geri gelmesi bekleniyor…",
      dnsUnavailable:
        "Yeniden başlarken DNS bir iki saniye kullanılamaz; cihazlar tekrar dener, bu yüzden genelde fark edilmez.",
      stillAnswering: " Hâlâ {live} olarak yanıt veriyor.",
      tookSeconds:
        "{seconds} saniye oldu. Önceki binary hâlâ diskte şu adla duruyor:",
      checkJournal: "— node üzerinde",
      onTheNode: "kontrol edin.",
    },
  },

  login: {
    setupIntro:
      "Bu node'un henüz bir yöneticisi yok. Kimi oluşturursa anahtarları o elinde tutar — başka bir şey panele erişmeden önce şimdi yapın.",
    signInIntro: "Bu node'u yönetmek için giriş yapın.",
    username: "Kullanıcı adı",
    password: "Parola",
    passwordHint: "En az 12 karakter. Bir parola cümlesi de olur.",
    twoFactorCode: "İki faktörlü kod",
    recoveryHint: "Bir kurtarma kodu da burada işe yarar.",
    createAdmin: "Yönetici oluştur",
    signIn: "Giriş yap",
  },

  panelPort: {
    where: "Bu panel nerede dinliyor",
    port: "port {port}",
    detail:
      "Bu makinedeki başka bir şey aynı portu istediğinde değiştirmeye değer. Cihazların isim sormak için gerçekten kullandığı port 53 bundan etkilenmez.",
    isOpen: "{port} portu açık. Henüz hiçbir şey kaydedilmedi.",
    confirmDetail:
      "Aşağıdaki adresi açıp oradan onaylayın. Yeni port üzerinden onaylanması gerekiyor — bu, portun bulunduğunuz yerden çalıştığını kanıtlayan tek şey, ve bu node'un kendi başına kontrol edemeyeceği tek şey de bu.",
    open: "{url} adresini aç",
    closesAt:
      "Hiçbir şey yapmazsanız port kendiliğinden şu saatte kapanır: {when}",
    closesShortly:
      "Hiçbir şey yapmazsanız port kendiliğinden kısa süre içinde kapanır",
    closesSuffix: ", panel tam olarak şu anki yerinde kalır.",
    cancelNow: "şimdi vazgeç",
    moveTo: "Şu porta taşı",
    openThatPort: "O portu aç",
    portRule:
      "1024 ya da üzeri. Daha düşük portlar bu node'un bilerek sahip olmadığı bir yetki gerektirir — bu, ağa açık olan kısım, ve zaten sahip olduğu tek istisna port 53.",
    saved: "Kaydedildi. Panel yeniden başlatmadan sonra da burada olacak.",
    reached: "Panele {port} portundan ulaştınız",
    proof:
      "Kanıt bu. Onaylarsanız bu, yeniden başlatmadan sonra da dahil olmak üzere panelin kullanacağı port olur. Hiçbir şey yapmazsanız eski haline döner.",
    keepPort: "Bu portu koru",
  },

  pairing: {
    title: "İkinci bir node eşleştir",
    detail:
      "İki node, kotoryum değil. Biri yapılandırmayı tutar, diğeri onu takip eder; ilki on beş saniye yanıt vermezse ikincisi kendini terfi ettirir. Üç makine oy vermenize izin verirdi, ama iki tanesi veremez — bu yüzden bu bilerek yapılan bir yük devretme.",
    close: "kapat",
    peerAddress: "Diğer node'un panel adresi",
    thisNodeIs: "Bu node",
    thePrimary: "primary",
    theReplica: "replica",
    sharedSecret: "Paylaşılan sır",
    couldNotGenerate: "burada üretilemedi",
    newOneBelow: "yenisi aşağıda",
    newToken: "yeni token",
    noRandomBytes:
      "Bu tarayıcı düz HTTP sayfasında rastgele bayt üretmeyecek. Onun yerine iki makineden birinde şunu çalıştırın —",
    noRandomBytesSuffix:
      "— ve aynı değeri her iki dosyaya da yapıştırın. Daha zayıfı işe yaramaz: bu, replikasyon portunu koruyan tek şey.",
    sameValue:
      "Aynı değer her iki node'a da gider. Replikasyon portu ile filtrelemeyi kapatan bir yapılandırma arasındaki tek şey bu, bu yüzden davet edilmek yerine burada üretiliyor — birinin aklına gelen bir sır, bunun aksi halde zayıf kalacak tek parçası.",
    editOnPrimary:
      "Yapılandırmayı primary üzerinde düzenleyin. Bir replica'nın kendi değişiklikleri bir sonraki senkronizasyonda üzerine yazılır, bu da bir öğleden sonranın emeğini kaybetmenin kafa karıştırıcı bir yolu.",
    onThisNode: "Bu node üzerinde ({host})",
    pasteRestart:
      "/etc/seddns/seddns.yaml içine yapıştırın, sonra şunu çalıştırın: systemctl restart seddns",
    fillOtherAddress:
      "Bu bloğu tamamlamak için yukarıya diğer node'un adresini girin.",
    onOtherNodeWithHost: "Diğer node üzerinde ({host})",
    onOtherNode: "Diğer node üzerinde",
    sameFileNote:
      "Aynı dosya, aynı yeniden başlatma. Her iki node da aynı token'a ihtiyaç duyar, yoksa hiçbiri diğerinin anlık görüntülerini kabul etmez.",
    then: "Sonra",
    step1:
      "İkisini de yeniden başlatın. Bu ekran birkaç saniye içinde diğer node'u göstermeye başlar.",
    step2:
      "Her iki adresi de DHCP üzerinden dağıtın, önce primary. Yük devretme yalnızca cihazlar nereye gideceğini biliyorsa işe yarar.",
    step3:
      "Router'ın kendisini asla ikincil olarak vermeyin. İlki yavaşladığı anda cihazlar ona kayar ve filtreleme hiçbir şey söylemeden durur.",
  },

  account: {
    lastSignedIn: "son giriş {when}",
    firstSession: "ilk oturum",
    passwordTitle: "Parola",
    passwordDetail:
      "Değiştirmek, bu tarayıcı dahil her tarayıcı ve cihazdaki oturumu kapatır — böylece çalınan bir oturum geldiği paroladan daha uzun ömürlü olamaz. Tekrar giriş yapmanız istenecek.",
    currentPassword: "Mevcut parola",
    newPassword: "Yeni parola",
    newPasswordHint: "en az 12 karakter",
    repeatPassword: "Yeni parolayı tekrarlayın",
    tooShort: "Bir parola en az 12 karakter olmalı.",
    mismatch: "İki yeni parola eşleşmiyor.",
    changeAndSignOut: "Parolayı değiştir ve çıkış yap",
    twoFactorOnSaveNow: "İki faktörlü doğrulama açık. Bunları şimdi kaydedin.",
    recoveryCodesWarning:
      "Kimlik doğrulayıcınızı kaybederseniz her kod bir kez giriş yapmanızı sağlar. Yalnızca burada gösteriliyor — node yalnızca özetlerini saklıyor, bu yüzden bu panel dahil hiç kimse bunları size tekrar gösteremez.",
    copyCodes: "Kodları kopyala",
    savedThem: "Kaydettim",
    twoFactor: "İki faktörlü doğrulama",
    onWithCodes: "açık · {count} kurtarma kodu kaldı",
    off: "kapalı",
    turnOffNeedsPassword:
      "Kapatmak parolanızı gerektirir, böylece açık bir oturumu ele geçiren biri sessizce kapatamaz.",
    password: "Parola",
    turnOff: "Kapat",
    addToAuthenticator:
      "Bunu kimlik doğrulayıcınıza ekleyin, sonra gösterdiği altı haneyi girin. İki faktörlü doğrulama yalnızca bir kod, sırrın bozulmadan ulaştığını kanıtladığında açılır.",
    codeFromApp: "Uygulamadan gelen kod",
    confirm: "Onayla",
    cancel: "vazgeç",
    whyItMatters:
      "İkinci bir faktör en çok burada önemli: bu panel evinizin çözdüğü her ismi yönlendirebilir, bu yüzden tahmin edilen bir parola tek engel olmamalı.",
    setUp: "İki faktörlü doğrulama kur",
  },
};
