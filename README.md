# 🔒 Güvenli Dosya Transferi ve Ağ Performans Test Sistemi



## 🎯 Proje Hakkında

Bu proje, **dosya güvenliği** ve **ağ performansı ölçümü** için kapsamlı bir sistem sunar. Gerçek zamanlı trafik kontrolü, AES-256 şifreleme, yüksek hızlı dosya transferi ve ayrıntılı test raporlamaları içerir.

---

## ⚡ Ana Özellikler

- 🔐 **AES-256 Şifreleme** – Askeri düzeyde veri güvenliği
- 📦 **Dosya Parçalama & Birleştirme** – Farklı boyutlarda veri yönetimi
- 🌐 **Ağ Performans Analizi** – iPerf3 ile 8+ Gbps test desteği
- 🔍 **Paket Analizi** – Scapy & Wireshark ile trafik incelemesi
- 📊 **Grafikli Raporlama** – Matplotlib ile gelişmiş veri görselleştirme
- 🛡️ **Bütünlük Kontrolü** – Checksum ile doğrulama testleri

---

## 📁 Proje Dosya Yapısı ve Açıklamaları

| Dosya Adı | Açıklama |
|----------|----------|
| `README.md` | Bu dokümantasyon dosyası |
| `enhanced_client.py` | Şifreli dosya transferi gerçekleştiren istemci uygulaması |
| `enhanced_server.py` | Gelen dosyaları alan, şifreyi çözen ve analiz yapan sunucu kodu |
| `fixed_test_system.py` | Tüm sistem testlerini (dosya, ağ, güvenlik) yöneten ana test modülü |
| `traffic_control_windows.py` | Windows platformunda trafik yönlendirmesi ve sınırlandırması yapan modül |
| `test_dosya.txt` | Test amacıyla kullanılan örnek veri dosyası |
| `test_raporu_20250608 180211.txt` | Gerçekleştirilen testlerin özet raporu (metin formatı) |
| `genel_rapor_20250608_212949.json` | Test çıktılarının JSON formatındaki ayrıntılı raporu |



---

## 💻 Demo: Terminal Çıktısı

```bash
🚀 ANA KONTROL SİSTEMİ BAŞLIYOR
═══════════════════════════════════════════════════════════

✅ DOSYA AKTARIM TESTLERİ
├── test_dosya_1024bytes.txt - Şifreleme/Çözme BAŞARILI
├── test_dosya_10240bytes.txt - Şifreleme/Çözme BAŞARILI  
├── test_dosya_102400bytes.txt - Şifreleme/Çözme BAŞARILI
└── test_dosya_1048576bytes.txt - Şifreleme/Çözme BAŞARILI

🔐 GÜVENLİK ANALİZİ
├── Algoritma: AES-256
├── Anahtar uzunluğu: 256 bit
└── Checksum: 0x9D72 ✅

⚡ AĞ PERFORMANS ÖLÇÜMÜ
├── Ping: 10.0 ms
├── Maksimum BW: 8041.9 Mbps
└── Test başarı oranı: %100
'''


## Test Aşamaları:

✅ Test Aşamaları
1️⃣ Dosya Testleri
✅ Dosya üretimi

✅ Parçalama / yeniden birleştirme

✅ Bütünlük ve checksum doğrulama

2️⃣ Şifreleme Testleri
✅ AES-256 şifreleme ve çözme

✅ Anahtar güvenliği

3️⃣ Ağ Testleri
✅ Ping ve gecikme ölçümü

✅ Bant genişliği ve QoS testleri

4️⃣ Trafik İzleme
✅ Gerçek zamanlı trafik görüntüleme

✅ IP başlık ve paket analiz


##📬 Katkı ve İletişim
Proje ile ilgili görüş, öneri veya katkılarınız için lütfen issue açın veya pull request gönderin. 🙌
Geliştirilmeye açık ve eğitimsel amaçlarla hazırlanmış bir projedir.

