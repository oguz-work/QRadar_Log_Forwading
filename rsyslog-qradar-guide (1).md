# Rsyslog ile QRadar'a Log İletimi - Ubuntu Kurulum Dökümanı

## 📋 Genel Bilgiler

- **Sistem**: Ubuntu (Son Versiyon)
- **Amaç**: Herhangi bir dizindeki log dosyasını QRadar SIEM'e syslog protokolü ile iletmek
- **Yöntem**: Rsyslog imfile modülü kullanımı
- **Protokol**: TCP/UDP Syslog (Port 514)

---

## 1. Rsyslog Durumunu Kontrol Et

```bash
# Rsyslog servisinin durumunu kontrol et
sudo systemctl status rsyslog

# Eğer yüklü değilse kur
sudo apt update
sudo apt install rsyslog -y

# Versiyon kontrolü
rsyslogd -v
```

---

## 2. Ana Rsyslog Yapılandırması

Ana rsyslog yapılandırma dosyasını düzenle:

```bash
sudo nano /etc/rsyslog.conf
```

Dosyanın **sonuna** aşağıdaki satırları ekle:

```bash
#############################
# QRadar Log Forwarding Configuration
#############################

# İmfile modülünü yükle (log dosyası okuma için)
module(load="imfile" PollingInterval="10")

# İzlenecek log dosyası tanımı
input(type="imfile"
      File="/var/log/uygulamam/app.log"
      Tag="ubuntu-app"
      StateFile="app-log-state"
      Severity="info"
      Facility="local0")

# QRadar'a TCP üzerinden gönderim (önerilen)
*.* @@192.168.1.100:514

# VEYA UDP kullanmak isterseniz (tek @ işareti)
# *.* @192.168.1.100:514
```

---

## 3. Parametre Açıklamaları

| Parametre | Açıklama | Örnek Değer |
|-----------|----------|-------------|
| **File** | İzlenecek log dosyasının tam yolu | `/var/log/uygulamam/app.log` |
| **Tag** | QRadar'da görünecek etiket | `ubuntu-app` |
| **StateFile** | Rsyslog'un dosya pozisyonunu takip ettiği dosya | `app-log-state` |
| **Severity** | Log seviyesi | `info`, `warning`, `error` |
| **Facility** | Syslog facility değeri | `local0` - `local7` |
| **@@** | TCP bağlantısı (çift @) | `@@192.168.1.100:514` |
| **@** | UDP bağlantısı (tek @) | `@192.168.1.100:514` |
| **PollingInterval** | Dosya kontrol süresi (saniye) | `10` |

---

## 4. Birden Fazla Log Dosyası İzleme

Birden fazla log dosyası izlemek için:

```bash
# İmfile modülünü yükle
module(load="imfile" PollingInterval="10")

# İlk log dosyası
input(type="imfile"
      File="/opt/myapp/logs/application.log"
      Tag="myapp"
      StateFile="myapp-state"
      Severity="info"
      Facility="local0")

# İkinci log dosyası
input(type="imfile"
      File="/var/log/nginx/access.log"
      Tag="nginx-access"
      StateFile="nginx-state"
      Severity="info"
      Facility="local1")

# Üçüncü log dosyası
input(type="imfile"
      File="/var/log/apache2/error.log"
      Tag="apache-error"
      StateFile="apache-state"
      Severity="error"
      Facility="local2")

# Tüm logları QRadar'a gönder
*.* @@192.168.1.100:514
```

---

## 5. Filtreleme ile Spesifik Gönderim

Sadece belirli logları göndermek için:

```bash
# Sadece local0 facility'sini QRadar'a gönder
local0.* @@192.168.1.100:514

# Sadece error ve üzeri logları gönder
*.error @@192.168.1.100:514

# Belirli tag'e sahip logları gönder
:syslogtag, isequal, "ubuntu-app:" @@192.168.1.100:514

# Gönderimden sonra logları durdur (duplicate önleme)
& stop
```

---

## 6. Rsyslog Servisini Yeniden Başlatma

```bash
# Yapılandırmayı test et (syntax kontrolü)
sudo rsyslogd -N1

# Servisi yeniden başlat
sudo systemctl restart rsyslog

# Durumu kontrol et
sudo systemctl status rsyslog

# Rsyslog'u enable et (boot'ta otomatik başlaması için)
sudo systemctl enable rsyslog
```

---

## 7. Test ve Doğrulama

### Test Mesajı Gönderme:
```bash
# Test log mesajı gönder
logger -t test-message "QRadar test mesajı - $(date)"

# Belirli facility ve priority ile test
logger -p local0.info "Test mesajı local0 facility"
```

### Log Kontrolü:
```bash
# Rsyslog loglarını kontrol et
sudo tail -f /var/log/syslog

# Rsyslog istatistikleri
sudo rsyslogd-pstats
```

### Bağlantı Kontrolü:
```bash
# TCP bağlantısını kontrol et
sudo netstat -an | grep 514
sudo ss -tunap | grep 514

# Telnet ile bağlantı testi
telnet 192.168.1.100 514
```

---

## 8. QRadar Tarafında Yapılandırma

### Log Source Oluşturma:

1. QRadar Console'a giriş yap
2. **Admin** → **Log Sources** → **Add**
3. Aşağıdaki bilgileri gir:

| Alan | Değer |
|------|-------|
| **Log Source Name** | Ubuntu-Rsyslog |
| **Log Source Type** | Syslog |
| **Protocol Type** | TCP veya UDP |
| **Log Source Identifier** | Ubuntu sunucu IP adresi |
| **Port** | 514 |
| **Enabled** | Yes |
| **Credibility** | 5 |
| **Target Event Collector** | Uygun Event Collector seç |

4. **DSM Seçimi**:
   - Generic DSM
   - Linux OS
   - Veya uygulamaya özel DSM

5. **Save** ve **Deploy Changes**

---

## 9. Performans Optimizasyonu

### Queue Yapılandırması:
```bash
# Yüksek hacimli loglar için queue kullanımı
$ActionQueueType LinkedList
$ActionQueueFileName qradar-queue
$ActionQueueMaxDiskSpace 1g
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on

# Rate limiting (saniyede max log sayısı)
$SystemLogRateLimitInterval 5
$SystemLogRateLimitBurst 500

@@192.168.1.100:514
```

### İmfile Modülü Optimizasyonu:
```bash
module(load="imfile" 
       PollingInterval="10"
       ReadTimeout="5000"
       PersistStateInterval="100")
```

---

## 10. Sorun Giderme

### Debug Modu:
```bash
# Rsyslog debug modunu aktif et
sudo rsyslogd -dn

# Verbose mod ile çalıştır
sudo rsyslogd -v
```

### İzin Kontrolleri:
```bash
# Log dosyası okuma izinleri
sudo chmod 644 /var/log/uygulamam/app.log
ls -la /var/log/uygulamam/

# AppArmor kontrolü (Ubuntu)
sudo aa-status | grep rsyslog

# AppArmor profili düzenleme (gerekirse)
sudo nano /etc/apparmor.d/usr.sbin.rsyslogd
```

### Firewall Kontrolleri:
```bash
# UFW durumu
sudo ufw status verbose

# Giden bağlantılar için port aç
sudo ufw allow out 514/tcp
sudo ufw allow out 514/udp

# İptables kontrolü
sudo iptables -L -n -v
```

### Log Kontrolü:
```bash
# Rsyslog hata logları
sudo grep rsyslog /var/log/syslog | tail -50
sudo journalctl -u rsyslog -f
```

---

## 11. Güvenlik Önerileri

### TLS/SSL ile Güvenli İletim:
```bash
# TLS modüllerini yükle
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1")

# Sertifika tanımlamaları
global(
    DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/rsyslog.d/client-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/client-key.pem"
)

# Güvenli gönderim
action(type="omfwd"
       Target="192.168.1.100"
       Port="6514"
       Protocol="tcp"
       StreamDriver="gtls"
       StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="qradar.example.com")
```

### Log Maskeleme:
```bash
# Hassas bilgileri maskele
$template MaskedLogs,"%timegenerated% %hostname% %syslogtag% %msg:R,ERE,0,DFLT:password=[^ ]+--password=REDACTED%\n"
*.* @@192.168.1.100:514;MaskedLogs
```

---

## 12. Örnek Senaryolar

### Senaryo 1: Web Sunucusu Logları
```bash
module(load="imfile" PollingInterval="10")

# Apache access log
input(type="imfile"
      File="/var/log/apache2/access.log"
      Tag="apache-access"
      StateFile="apache-access-state"
      Facility="local0")

# Apache error log
input(type="imfile"
      File="/var/log/apache2/error.log"
      Tag="apache-error"
      StateFile="apache-error-state"
      Facility="local1")

*.* @@192.168.1.100:514
```

### Senaryo 2: Docker Container Logları
```bash
module(load="imfile" PollingInterval="5")

input(type="imfile"
      File="/var/lib/docker/containers/*/*.log"
      Tag="docker"
      StateFile="docker-state"
      Facility="local2")

*.* @@192.168.1.100:514
```

### Senaryo 3: Özel Uygulama Logları
```bash
module(load="imfile" PollingInterval="10")

# JSON formatında log
input(type="imfile"
      File="/opt/myapp/logs/app.json"
      Tag="myapp-json"
      StateFile="myapp-json-state"
      Facility="local3"
      addMetadata="on")

# Multi-line log desteği
input(type="imfile"
      File="/opt/myapp/logs/stacktrace.log"
      Tag="myapp-stack"
      StateFile="myapp-stack-state"
      Facility="local4"
      readMode="2")

*.* @@192.168.1.100:514
```

---

## 13. Monitoring ve Alerting

### Rsyslog İstatistikleri:
```bash
# İstatistik modülünü aktif et
module(load="impstats"
       interval="300"
       severity="7"
       log.syslog="on")

# Veya dosyaya yaz
module(load="impstats"
       interval="60"
       severity="7"
       log.file="/var/log/rsyslog-stats.log")
```

### Health Check Script:
```bash
#!/bin/bash
# rsyslog_health_check.sh

# Servis durumu kontrol
if ! systemctl is-active --quiet rsyslog; then
    echo "CRITICAL: Rsyslog service is not running"
    systemctl start rsyslog
    exit 2
fi

# Bağlantı kontrol
if ! nc -zv 192.168.1.100 514 2>/dev/null; then
    echo "WARNING: Cannot connect to QRadar"
    exit 1
fi

echo "OK: Rsyslog is running and connected to QRadar"
exit 0
```

---

## 14. Temizlik ve Bakım

### Log Rotation:
```bash
# /etc/logrotate.d/rsyslog-qradar
/var/log/rsyslog-stats.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
}
```

### State File Temizliği:
```bash
# Eski state dosyalarını temizle
find /var/spool/rsyslog -name "*-state" -mtime +30 -delete
```

---

## 15. Hızlı Referans - Komutlar

```bash
# Servis yönetimi
sudo systemctl start rsyslog
sudo systemctl stop rsyslog
sudo systemctl restart rsyslog
sudo systemctl status rsyslog

# Yapılandırma test
sudo rsyslogd -N1

# Log takibi
sudo tail -f /var/log/syslog
sudo journalctl -u rsyslog -f

# Test mesajı
logger -t test "Test message"
logger -p local0.info "Test with facility"

# Bağlantı kontrol
telnet 192.168.1.100 514
nc -zv 192.168.1.100 514
```

---

## 📝 Notlar

- **IP Adresi**: `192.168.1.100` yerine kendi QRadar IP adresinizi yazın
- **Log Dosya Yolu**: `/var/log/uygulamam/app.log` yerine kendi log dosya yolunuzu yazın
- **Tag İsimleri**: Anlamlı ve unique tag isimleri kullanın
- **StateFile**: Her log dosyası için farklı StateFile adı kullanın
- **Test**: Yapılandırma sonrası mutlaka test edin

---

## 🔗 Faydalı Kaynaklar

- [Rsyslog Official Documentation](https://www.rsyslog.com/doc/)
- [QRadar DSM Configuration Guide](https://www.ibm.com/docs/en/qradar-common)
- [Syslog RFC 3164](https://tools.ietf.org/html/rfc3164)
- [Syslog RFC 5424](https://tools.ietf.org/html/rfc5424)

---

**Döküman Sürümü**: 1.0  
**Oluşturma Tarihi**: 2025  
**Platform**: Ubuntu (Son Versiyon) + Rsyslog + QRadar SIEM