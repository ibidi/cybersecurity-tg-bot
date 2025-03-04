import os
import logging
import re
import requests
import validators
import dns.resolver
import socket
import whois
import ssl
import datetime
import hashlib
import json
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, quote_plus
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from password_strength import PasswordStats

# Logging ayarları
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# .env dosyasından token'ı yükle
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot başlatıldığında çalışacak komut"""
    user = update.effective_user
    keyboard = [
        [InlineKeyboardButton("🔐 Şifre Kontrolü", callback_data='password_check'),
         InlineKeyboardButton("🌐 Site Güvenliği", callback_data='site_check')],
        [InlineKeyboardButton("🔍 Port Tarama", callback_data='port_scan'),
         InlineKeyboardButton("🌍 DNS Bilgisi", callback_data='dns_info')],
        [InlineKeyboardButton("📜 SSL Kontrol", callback_data='ssl_check'),
         InlineKeyboardButton("🔎 IP Analizi", callback_data='ip_analysis')],
        [InlineKeyboardButton("🔄 Hash İşlemleri", callback_data='hash_ops'),
         InlineKeyboardButton("🌐 Subdomain Tarama", callback_data='subdomain_scan')],
        [InlineKeyboardButton("🛡️ CVE Arama", callback_data='cve_search'),
         InlineKeyboardButton("📚 Güvenlik İpuçları", callback_data='security_tips')],
        [InlineKeyboardButton("🔍 Google Dork Tarama", callback_data='dork_search'),
         InlineKeyboardButton("❓ Yardım", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f'Merhaba {user.first_name}! Ben bir Siber Güvenlik botuyum.\n'
        'Size aşağıdaki konularda yardımcı olabilirim:\n\n'
        '🔐 /password <şifre> - Şifre güvenlik kontrolü\n'
        '🌐 /site <url> - Site güvenlik kontrolü\n'
        '🔍 /port <host> - Port taraması\n'
        '🌍 /dns <domain> - DNS bilgisi sorgulama\n'
        '📜 /ssl <domain> - SSL sertifika kontrolü\n'
        '🔎 /ip <ip> - IP adresi analizi\n'
        '🔄 /hash <metin> - Hash hesaplama\n'
        '🔄 /verify <hash> <metin> - Hash doğrulama\n'
        '🌐 /subdomain <domain> - Subdomain tarama\n'
        '🛡️ /cve <anahtar> - CVE arama\n'
        '📚 /tips - Güvenlik ipuçları\n'
        '🔍 /dork <domain> - Google Dork tarama\n'
        '❓ /help - Yardım menüsü\n\n'
        'Veya aşağıdaki butonları kullanabilirsiniz:',
        reply_markup=reply_markup
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Yardım komutu"""
    help_text = """
    🔐 Kullanabileceğiniz komutlar:
    
    /start - Botu başlat
    /help - Bu yardım menüsünü göster
    /check_password <şifre> - Şifrenizin güvenliğini kontrol edin
    /check_site <url> - Web sitesinin güvenliğini kontrol edin
    /scan_ports <host> - Belirtilen host'un açık portlarını tara
    /dns_lookup <domain> - Domain DNS bilgilerini sorgula
    /check_ssl <domain> - SSL sertifika bilgilerini kontrol et
    /ip_info <ip> - IP adresi hakkında bilgi al
    /hash <metin> - Metin için hash değerlerini hesapla
    /verify_hash <hash> <metin> - Hash değerini doğrula
    /scan_subdomains <domain> - Subdomain taraması yap
    /cve_search <anahtar_kelime> - CVE veritabanında ara
    /security_tips - Siber güvenlik ipuçlarını görüntüleyin
    /dork <domain> - Google Dork taraması yap
    """
    await update.message.reply_text(help_text)

async def check_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Şifre güvenliğini kontrol eden komut"""
    if not context.args:
        await update.message.reply_text("Lütfen kontrol edilecek şifreyi girin.\nÖrnek: /check_password MyPassword123")
        return

    password = ' '.join(context.args)
    stats = PasswordStats(password)
    
    # Şifre güvenlik kriterleri kontrolü
    strength = stats.strength()
    entropy = stats.entropy_bits
    
    result = "🔐 Şifre Analizi:\n\n"
    result += f"Güvenlik Puanı: {strength * 10:.1f}/10\n"
    result += f"Entropi: {entropy:.1f} bits\n\n"
    
    # Şifre kontrolleri
    checks = {
        "Uzunluk (min. 12)": len(password) >= 12,
        "Büyük harf": bool(re.search(r'[A-Z]', password)),
        "Küçük harf": bool(re.search(r'[a-z]', password)),
        "Rakam": bool(re.search(r'\d', password)),
        "Özel karakter": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    
    for check, passed in checks.items():
        result += f"{'✅' if passed else '❌'} {check}\n"
    
    await update.message.reply_text(result)

async def check_site(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Web sitesi güvenliğini kontrol eden komut"""
    if not context.args:
        await update.message.reply_text("Lütfen kontrol edilecek web sitesi URL'sini girin.\nÖrnek: /check_site example.com")
        return

    url = ' '.join(context.args)
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    if not validators.url(url):
        await update.message.reply_text("❌ Geçersiz URL formatı!")
        return
        
    try:
        response = requests.get(url, timeout=5)
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection')
        }
        
        result = f"🔒 {url} Güvenlik Analizi:\n\n"
        result += f"HTTPS: {'✅' if response.url.startswith('https://') else '❌'}\n\n"
        result += "Güvenlik Başlıkları:\n"
        
        for header, value in security_headers.items():
            result += f"{header}: {'✅' if value else '❌'}\n"
            
    except requests.RequestException:
        result = "❌ Site bağlantısı kurulamadı veya zaman aşımına uğradı."
    
    await update.message.reply_text(result)

async def security_tips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Siber güvenlik ipuçlarını gösteren komut"""
    tips = """
🔐 Önemli Siber Güvenlik İpuçları:

1. Güçlü Şifreler:
   • En az 12 karakter uzunluğunda
   • Büyük/küçük harf, rakam ve özel karakterler içermeli
   • Her hesap için farklı şifre kullanın

2. İki Faktörlü Doğrulama (2FA):
   • Mümkün olan her yerde aktifleştirin
   • SMS yerine authenticator uygulamaları tercih edin

3. Güncellemeler:
   • İşletim sistemi ve uygulamaları güncel tutun
   • Otomatik güncellemeleri aktif edin

4. Güvenli İnternet:
   • Şüpheli bağlantılara tıklamayın
   • Güvenli olmayan WiFi ağlarında VPN kullanın
   • HTTPS protokolü kullanan siteleri tercih edin

5. Yedekleme:
   • Önemli verilerinizi düzenli olarak yedekleyin
   • 3-2-1 yedekleme kuralını uygulayın
"""
    await update.message.reply_text(tips)

async def scan_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Belirtilen host'un açık portlarını tarar"""
    if not context.args:
        await update.message.reply_text("Lütfen bir host adı veya IP adresi girin.\nÖrnek: /scan_ports example.com")
        return

    host = context.args[0]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    result = f"🔍 Port Tarama Sonuçları ({host}):\n\n"
    
    try:
        ip = socket.gethostbyname(host)
        result += f"IP Adresi: {ip}\n\n"
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            if sock.connect_ex((ip, port)) == 0:
                service = socket.getservbyport(port)
                result += f"✅ Port {port} ({service}): Açık\n"
            sock.close()
            
    except socket.gaierror:
        result = "❌ Geçersiz host adı veya IP adresi!"
    except socket.error:
        result = "❌ Bağlantı hatası!"
        
    await update.message.reply_text(result)

async def dns_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Domain DNS bilgilerini sorgular"""
    if not context.args:
        await update.message.reply_text("Lütfen bir domain adı girin.\nÖrnek: /dns_lookup example.com")
        return

    domain = context.args[0]
    result = f"🌍 DNS Bilgileri ({domain}):\n\n"
    
    try:
        # A kaydı
        a_records = dns.resolver.resolve(domain, 'A')
        result += "📍 A Kayıtları:\n"
        for record in a_records:
            result += f"  • {record}\n"
            
        # MX kaydı
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result += "\n📧 MX Kayıtları:\n"
            for record in mx_records:
                result += f"  • {record.exchange} (Öncelik: {record.preference})\n"
        except dns.resolver.NoAnswer:
            result += "\n❌ MX kaydı bulunamadı\n"
            
        # NS kaydı
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result += "\n🌐 NS Kayıtları:\n"
            for record in ns_records:
                result += f"  • {record}\n"
        except dns.resolver.NoAnswer:
            result += "\n❌ NS kaydı bulunamadı\n"
            
        # WHOIS bilgisi
        try:
            w = whois.whois(domain)
            result += f"\n📋 WHOIS Bilgisi:\n"
            result += f"  • Kayıt Tarihi: {w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date}\n"
            result += f"  • Bitiş Tarihi: {w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date}\n"
            result += f"  • Registrar: {w.registrar}\n"
        except Exception:
            result += "\n❌ WHOIS bilgisi alınamadı\n"
            
    except dns.resolver.NXDOMAIN:
        result = "❌ Domain bulunamadı!"
    except dns.resolver.NoAnswer:
        result = "❌ DNS kayıtları bulunamadı!"
    except Exception as e:
        result = f"❌ Hata oluştu: {str(e)}"
        
    await update.message.reply_text(result)

async def check_ssl(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """SSL sertifika bilgilerini kontrol eder"""
    if not context.args:
        await update.message.reply_text("Lütfen bir domain adı girin.\nÖrnek: /check_ssl example.com")
        return

    domain = context.args[0]
    result = f"🔒 SSL Sertifika Bilgileri ({domain}):\n\n"
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Sertifika bilgileri
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                
                # Sertifika sahibi ve sağlayıcı bilgilerini güvenli şekilde al
                subject_dict = dict(x[0] for x in cert['subject'])
                issuer_dict = dict(x[0] for x in cert['issuer'])
                
                result += f"Sertifika Sahibi: {subject_dict.get('commonName', 'Bilinmiyor')}\n"
                result += f"Sertifika Sağlayıcı: {issuer_dict.get('commonName', 'Bilinmiyor')}\n"
                result += f"Geçerlilik Başlangıcı: {not_before.strftime('%d.%m.%Y')}\n"
                result += f"Geçerlilik Bitişi: {not_after.strftime('%d.%m.%Y')}\n"
                
                # Alternatif domain adları
                if 'subjectAltName' in cert:
                    alt_names = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']
                    if alt_names:
                        result += "\nAlternatif Domain Adları:\n"
                        for name in alt_names[:5]:  # İlk 5 alternatif adı göster
                            result += f"  • {name}\n"
                        if len(alt_names) > 5:
                            result += f"  ... ve {len(alt_names) - 5} domain daha\n"
                
                # Sertifika durumu
                now = datetime.datetime.now()
                if now < not_after:
                    days_left = (not_after - now).days
                    if days_left > 30:
                        result += f"\n✅ Sertifika Geçerli (Kalan: {days_left} gün)"
                    else:
                        result += f"\n⚠️ Sertifika yakında sona erecek! (Kalan: {days_left} gün)"
                else:
                    result += "\n❌ Sertifika Süresi Dolmuş!"
                    
    except ssl.SSLError:
        result = "❌ SSL sertifikası bulunamadı veya geçersiz!"
    except socket.gaierror:
        result = "❌ Domain adı çözümlenemedi!"
    except Exception as e:
        result = f"❌ Hata oluştu: {str(e)}"
        
    await update.message.reply_text(result)

async def ip_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """IP adresi hakkında detaylı bilgi verir"""
    if not context.args:
        await update.message.reply_text("Lütfen bir IP adresi girin.\nÖrnek: /ip_info 8.8.8.8")
        return

    ip = context.args[0]
    result = f"🔎 IP Analizi ({ip}):\n\n"
    
    try:
        # IP API'den bilgi al
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data['status'] == 'success':
            result += f"📍 Konum: {data.get('country', 'Bilinmiyor')}, {data.get('city', 'Bilinmiyor')}\n"
            result += f"🌐 ISP: {data.get('isp', 'Bilinmiyor')}\n"
            result += f"🏢 Organizasyon: {data.get('org', 'Bilinmiyor')}\n"
            result += f"⚡ AS: {data.get('as', 'Bilinmiyor')}\n"
            result += f"🌍 Koordinatlar: {data.get('lat', '?')}, {data.get('lon', '?')}\n"
            result += f"⏰ Zaman Dilimi: {data.get('timezone', 'Bilinmiyor')}\n"
            
            # Tehdit kontrolü
            try:
                abuse_response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                                           headers={'Key': os.getenv('ABUSEIPDB_KEY', '')})
                abuse_data = abuse_response.json()
                if 'data' in abuse_data:
                    score = abuse_data['data']['abuseConfidenceScore']
                    result += f"\n🛡️ Tehdit Skoru: {score}%"
                    if score > 50:
                        result += " ⚠️ Yüksek risk!"
            except:
                pass
                
        else:
            result = "❌ IP bilgisi alınamadı!"
            
    except Exception as e:
        result = f"❌ Hata oluştu: {str(e)}"
        
    await update.message.reply_text(result)

async def calculate_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Metin için çeşitli hash değerlerini hesaplar"""
    if not context.args:
        await update.message.reply_text("Lütfen hash'i hesaplanacak metni girin.\nÖrnek: /hash merhaba123")
        return

    text = ' '.join(context.args)
    result = "🔄 Hash Değerleri:\n\n"
    
    # Çeşitli hash algoritmaları
    algorithms = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
        'SHA512': hashlib.sha512()
    }
    
    for name, hasher in algorithms.items():
        hasher.update(text.encode())
        result += f"{name}: `{hasher.hexdigest()}`\n"
    
    await update.message.reply_text(result, parse_mode='Markdown')

async def verify_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Hash değerini verilen metin ile doğrular"""
    if len(context.args) < 2:
        await update.message.reply_text("Lütfen hash değeri ve metni girin.\nÖrnek: /verify_hash 5d41402abc4b2a76b9719d911017c592 hello")
        return

    hash_value = context.args[0].lower()
    text = ' '.join(context.args[1:])
    result = "🔍 Hash Doğrulama:\n\n"
    
    # Hash uzunluğuna göre algoritma belirleme
    hash_lengths = {
        32: 'MD5',
        40: 'SHA1',
        64: 'SHA256',
        128: 'SHA512'
    }
    
    algorithm = hash_lengths.get(len(hash_value), None)
    if not algorithm:
        result += "❌ Geçersiz hash uzunluğu!"
        await update.message.reply_text(result)
        return
    
    # Hash hesaplama ve karşılaştırma
    hasher = getattr(hashlib, algorithm.lower())()
    hasher.update(text.encode())
    calculated_hash = hasher.hexdigest()
    
    result += f"Algoritma: {algorithm}\n"
    result += f"Beklenen Hash: `{hash_value}`\n"
    result += f"Hesaplanan Hash: `{calculated_hash}`\n\n"
    
    if hash_value == calculated_hash:
        result += "✅ Hash değerleri eşleşiyor!"
    else:
        result += "❌ Hash değerleri eşleşmiyor!"
    
    await update.message.reply_text(result, parse_mode='Markdown')

async def scan_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Domain için subdomain taraması yapar"""
    if not context.args:
        await update.message.reply_text("Lütfen bir domain adı girin.\nÖrnek: /scan_subdomains example.com")
        return

    domain = context.args[0]
    result = f"🌐 Subdomain Taraması ({domain}):\n\n"
    found_subdomains = set()
    
    try:
        # DNS kayıtlarından subdomain arama
        common_prefixes = ['www', 'mail', 'ftp', 'smtp', 'pop', 'api', 'dev', 'admin', 'blog', 'shop', 
                         'store', 'app', 'mobile', 'test', 'staging', 'beta', 'alpha', 'demo']
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                for answer in answers:
                    found_subdomains.add(f"{subdomain} ({answer})")
            except:
                continue
                
        # Sertifika şeffaflık loglarından subdomain arama
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(ct_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry['name_value'].lower()
                            if '*' not in name:  # Wildcard sertifikaları hariç tut
                                found_subdomains.add(name)
        except:
            pass
            
        if found_subdomains:
            result += "Bulunan Subdomainler:\n"
            for subdomain in sorted(found_subdomains)[:20]:  # İlk 20 sonucu göster
                result += f"  • {subdomain}\n"
            
            if len(found_subdomains) > 20:
                result += f"\n... ve {len(found_subdomains) - 20} subdomain daha"
        else:
            result += "❌ Subdomain bulunamadı!"
            
    except Exception as e:
        result = f"❌ Hata oluştu: {str(e)}"
        
    await update.message.reply_text(result)

async def search_cve(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """CVE veritabanında arama yapar"""
    if not context.args:
        await update.message.reply_text("Lütfen arama terimini girin.\nÖrnek: /cve_search apache log4j")
        return

    search_term = ' '.join(context.args)
    result = f"🛡️ CVE Arama Sonuçları ({search_term}):\n\n"
    
    try:
        # NVD API'den CVE bilgisi al
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}"
        response = requests.get(url)
        data = response.json()
        
        if 'vulnerabilities' in data:
            vulns = data['vulnerabilities'][:5]  # İlk 5 sonucu göster
            
            for vuln in vulns:
                cve = vuln['cve']
                result += f"CVE ID: {cve['id']}\n"
                result += f"Yayın Tarihi: {cve.get('published', 'Bilinmiyor')}\n"
                result += f"Önem Derecesi: {cve.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'Bilinmiyor')}\n"
                result += f"Açıklama: {cve.get('descriptions', [{}])[0].get('value', 'Açıklama yok')}\n\n"
                
            if len(data['vulnerabilities']) > 5:
                result += f"... ve {len(data['vulnerabilities']) - 5} sonuç daha\n"
        else:
            result += "❌ Sonuç bulunamadı!"
            
    except Exception as e:
        result = f"❌ Hata oluştu: {str(e)}"
        
    await update.message.reply_text(result)

async def dork_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Google Dork menüsünü gösterir"""
    keyboard = [
        [InlineKeyboardButton("🔍 Açık Dizinler", callback_data='dork_directories')],
        [InlineKeyboardButton("📁 Gizli Dosyalar", callback_data='dork_files')],
        [InlineKeyboardButton("⚙️ Yapılandırma Dosyaları", callback_data='dork_config')],
        [InlineKeyboardButton("💾 Veritabanı Dosyaları", callback_data='dork_database')],
        [InlineKeyboardButton("🔐 Giriş Sayfaları", callback_data='dork_login')],
        [InlineKeyboardButton("⚠️ Hassas Dizinler", callback_data='dork_sensitive')],
        [InlineKeyboardButton("❌ Hata Mesajları", callback_data='dork_errors')],
        [InlineKeyboardButton("🌐 Teknoloji Bilgisi", callback_data='dork_tech')],
        [InlineKeyboardButton("🔙 Ana Menü", callback_data='main_menu')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🔍 Google Dork Tarama Menüsü\n\n"
        "Lütfen taramak istediğiniz kategoriyi seçin:",
        reply_markup=reply_markup
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Buton tıklamalarını işleyen fonksiyon"""
    query = update.callback_query
    await query.answer()
    
    if query.data == 'password_check':
        await query.message.reply_text(
            "🔐 Şifre güvenlik kontrolü için:\n"
            "/password <şifre>\n"
            "Örnek: /password MySecurePass123"
        )
    elif query.data == 'site_check':
        await query.message.reply_text(
            "🌐 Site güvenlik kontrolü için:\n"
            "/site <url>\n"
            "Örnek: /site example.com"
        )
    elif query.data == 'port_scan':
        await query.message.reply_text(
            "🔍 Port taraması için:\n"
            "/port <host>\n"
            "Örnek: /port example.com"
        )
    elif query.data == 'dns_info':
        await query.message.reply_text(
            "🌍 DNS bilgisi sorgulamak için:\n"
            "/dns <domain>\n"
            "Örnek: /dns example.com"
        )
    elif query.data == 'ssl_check':
        await query.message.reply_text(
            "📜 SSL sertifika kontrolü için:\n"
            "/ssl <domain>\n"
            "Örnek: /ssl example.com"
        )
    elif query.data == 'ip_analysis':
        await query.message.reply_text(
            "🔎 IP adresi analizi için:\n"
            "/ip <ip>\n"
            "Örnek: /ip 8.8.8.8"
        )
    elif query.data == 'hash_ops':
        await query.message.reply_text(
            "🔄 Hash işlemleri için:\n"
            "/hash <metin> - Hash hesaplama\n"
            "/verify <hash> <metin> - Hash doğrulama\n"
            "Örnek:\n"
            "/hash merhaba123\n"
            "/verify 5d41402abc4b2a76b9719d911017c592 hello"
        )
    elif query.data == 'subdomain_scan':
        await query.message.reply_text(
            "🌐 Subdomain taraması için:\n"
            "/subdomain <domain>\n"
            "Örnek: /subdomain example.com"
        )
    elif query.data == 'cve_search':
        await query.message.reply_text(
            "🛡️ CVE veritabanında arama yapmak için:\n"
            "/cve <anahtar>\n"
            "Örnek: /cve apache log4j"
        )
    elif query.data == 'security_tips':
        await security_tips(query, context)
    elif query.data == 'help':
        await help_command(query, context)
    elif query.data == 'dork_search':
        keyboard = [
            [InlineKeyboardButton("🔍 Açık Dizinler", callback_data='dork_directories')],
            [InlineKeyboardButton("📁 Gizli Dosyalar", callback_data='dork_files')],
            [InlineKeyboardButton("⚙️ Yapılandırma Dosyaları", callback_data='dork_config')],
            [InlineKeyboardButton("💾 Veritabanı Dosyaları", callback_data='dork_database')],
            [InlineKeyboardButton("🔐 Giriş Sayfaları", callback_data='dork_login')],
            [InlineKeyboardButton("⚠️ Hassas Dizinler", callback_data='dork_sensitive')],
            [InlineKeyboardButton("❌ Hata Mesajları", callback_data='dork_errors')],
            [InlineKeyboardButton("🌐 Teknoloji Bilgisi", callback_data='dork_tech')],
            [InlineKeyboardButton("🔙 Ana Menü", callback_data='main_menu')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.edit_text(
            "🔍 Google Dork Tarama Menüsü\n\n"
            "Komut ile kullanmak için:\n"
            "/dork <domain>\n"
            "Örnek: /dork example.com\n\n"
            "Veya aşağıdaki kategorilerden birini seçin:",
            reply_markup=reply_markup
        )
    elif query.data == 'main_menu':
        await start(query, context)

def main():
    """Bot'u başlatan ana fonksiyon"""
    application = Application.builder().token(TOKEN).build()

    # Komut işleyicilerini ekle
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("password", check_password))
    application.add_handler(CommandHandler("site", check_site))
    application.add_handler(CommandHandler("port", scan_ports))
    application.add_handler(CommandHandler("dns", dns_lookup))
    application.add_handler(CommandHandler("ssl", check_ssl))
    application.add_handler(CommandHandler("ip", ip_info))
    application.add_handler(CommandHandler("hash", calculate_hash))
    application.add_handler(CommandHandler("verify", verify_hash))
    application.add_handler(CommandHandler("subdomain", scan_subdomains))
    application.add_handler(CommandHandler("cve", search_cve))
    application.add_handler(CommandHandler("tips", security_tips))
    application.add_handler(CommandHandler("dork", dork_menu))
    
    # Buton işleyicisini ekle
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Metin mesajı işleyicisi ekle
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, button_handler))

    # Botu başlat
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main() 