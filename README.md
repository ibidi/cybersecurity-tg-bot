# 🛡️ Siber Güvenlik Telegram Botu

Bu Telegram botu, siber güvenlik alanında çeşitli araçlar ve kontroller sunan kapsamlı bir yardımcıdır.

## 🚀 Özellikler

### 🔐 Güvenlik Kontrolleri
- `/password` - Şifre güvenlik analizi
- `/site` - Web sitesi güvenlik kontrolü
- `/ssl` - SSL sertifika kontrolü
- `/ip` - IP adresi analizi

### 🌐 Ağ Araçları
- `/port` - Port taraması
- `/dns` - DNS kayıt sorgulaması
- `/subdomain` - Subdomain taraması

### 🔍 Google Dork Taraması
- `/dork` - Google Dork kategorileri ile güvenlik taraması
  - Açık Dizinler
  - Gizli Dosyalar
  - Yapılandırma Dosyaları
  - Veritabanı Dosyaları
  - Giriş Sayfaları
  - Hassas Dizinler
  - Hata Mesajları
  - Teknoloji Bilgisi

### 🔄 Hash İşlemleri
- `/hash` - Metin için hash hesaplama (MD5, SHA1, SHA256, SHA512)
- `/verify` - Hash doğrulama

### 🛡️ Güvenlik Araştırması
- `/cve` - CVE veritabanında arama
- `/tips` - Siber güvenlik ipuçları

## 🛠️ Kurulum

1. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

2. `.env` dosyası oluşturun ve Telegram Bot Token'ınızı ekleyin:
```
TELEGRAM_BOT_TOKEN=your_token_here
```

3. Botu çalıştırın:
```bash
python bot.py
```

## 📚 Kullanım Örnekleri

```
/password MySecurePass123
/site example.com
/port example.com
/dns example.com
/ssl example.com
/ip 8.8.8.8
/hash merhaba123
/verify 5d41402abc4b2a76b9719d911017c592 hello
/subdomain example.com
/cve apache log4j
/dork example.com
```

## 🔧 Gereksinimler

- Python 3.8+
- python-telegram-bot==20.7
- python-dotenv==1.0.0
- requests==2.31.0
- password-strength==0.0.3.post2
- pysafebrowsing==0.1.2
- validators==0.22.0
- dnspython==2.6.1
- python-whois==0.8.0
- cryptography==42.0.5

## 🤝 Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir özellik dalı oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Dalınıza push yapın (`git push origin yeni-ozellik`)
5. Bir Pull Request oluşturun

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

## ⚠️ Sorumluluk Reddi

Bu bot yalnızca eğitim amaçlıdır. Kötü niyetli kullanımdan kullanıcı sorumludur. 