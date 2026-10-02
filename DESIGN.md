# DESIGN.md — Secure Vault görsel kararları

Bu dosya ürünün tasarım sistemidir. UI üreten herkes (insan/AI) buraya uyar.

## Fikir (point of view)

Bir banka kasası dairesi gibi hissettirmeli: sessiz, ağır, mekanik. Dekorasyon yok;
güven veren şey süs değil **hassasiyet**: hizalı sayılar, gerçek durumlar, her
tıklamada cevap veren arayüz.

## Dials

ENERGY 2 / RHYTHM 2 / MOTION 2 — sıcak karşılama, asimetrik kilit ekranı, overlay
montaj animasyonları + basma mikro-etkisi + dönen kasa-çarkı motifi. Liste içeriği
animasyonsuz belirir (içerik varsayılan görünür).

## Jetonlar

- Zemin: `#14120f` (sıcak koyu), panel `#1c1a16`, saç çizgisi `rgba(255,255,255,.08)`
- Tek vurgu: kehribar `#e8a33d` — SADECE birincil eylem + "açık dosya" noktası + focus halkası
- Anlam renkleri: başarı `#4caf7d`, tehlike `#d4573e` (sadece ilgili yerde)
- YASAK: mor/mavi gradient, cam efektli kart, glow, emoji ikon, her yerde 16px radius
- Yazı: arayüz `Segoe UI Variable`, marka/boş durum başlığı `Georgia` serif, id/boyut/durum çubuğu `Cascadia Mono, Consolas` mono + tabular sayılar
- Radius: kontrol 8px, kart 10px. Satır yüksekliği: liste 40px, komut paleti 36px
- Hareket: sadece 120ms hover/focus geçişleri. Giriş animasyonu YOK (içerik varsayılan görünür).
  `prefers-reduced-motion` varsa geçişler kapanır.

## Desenler

- Liste öncelikli: dosyalar tablo satırı (ikon + isim + mono boyut + göreli zaman + hover'da eylemler)
- Komut paleti (`Ctrl+K`): dosyalar + eylemler, klavye ile gezinme — güç kullanıcılarının omurgası
- Boş durumlar tasarlanmış: serif başlık + tek cümle + tek eylem butonu
- Her butonda: default / hover / focus-visible / active / disabled hali
- Kopya dili kısa ve somut: kategori değil iddia ("10 dk boşta kalınca kilitlenir")
