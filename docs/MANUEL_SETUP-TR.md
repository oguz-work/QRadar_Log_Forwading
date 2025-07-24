# QRadar Manuel Log Forwarding Kurulum Rehberi

## İçindekiler

1. [Giriş ve Gereksinimler](#giriş-ve-gereksinimler)
2. [Debian/Ubuntu Kurulum](#debianubuntu-kurulum)
3. [RHEL/CentOS/Rocky/AlmaLinux Kurulum](#rhelcentosrockyalmalinux-kurulum)
4. [Kurulum Doğrulaması](#kurulum-doğrulaması)
5. [Temel Sorun Giderme](#temel-sorun-giderme)

---

## Giriş ve Gereksinimler

Bu rehber, Linux sistemlerden IBM QRadar SIEM'e audit loglarının manuel olarak yönlendirilmesi için adım adım kurulum kılavuzudur.

### Sistem Gereksinimleri

- **Root Yetkisi**: `sudo` veya `root` erişimi
- **QRadar Sunucusu**: Aktif QRadar sunucusu ve log source konfigürasyonu
- **Ağ Bağlantısı**: QRadar IP ve portuna TCP erişimi

### Kurulum Bileşenleri

- **auditd**: Sistem audit olaylarını toplama
- **rsyslog**: TCP protokolü ile QRadar'a yönlendirme  
- **Python Parser**: EXECVE loglarını işleme

---

## Debian/Ubuntu Kurulum

### Adım 1: Paket Kurulumu

```bash
# Sistem paketlerini güncelle
sudo apt-get update

# Gerekli paketleri kur
sudo apt-get install -y auditd audispd-plugins rsyslog python3
```

### Adım 2: Audit Kuralları Konfigürasyonu

```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
```

Aşağıdaki kuralları dosyaya ekleyin:

```bash
# QRadar Audit Kuralları
-D
-b 16384
-f 1
-r 150

# Kimlik doğrulama ve yetki dosyaları
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# SSH konfigürasyonu
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys

# Komut çalıştırma izleme
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Sistem yönetim araçları
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/ssh -p x -k remote_access

# Ağ konfigürasyonu
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config

# Zamanlanmış görevler
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks

# Sistem servisleri
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services

# Log dosyaları
-w /var/log/auth.log -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
```

### Adım 3: Audispd Syslog Konfigürasyonu

```bash
# Ubuntu 20.04+ ve Debian 10+ için
sudo nano /etc/audit/plugins.d/syslog.conf

# Eski versiyonlar için
sudo nano /etc/audisp/plugins.d/syslog.conf
```

Dosya içeriği:
```bash
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
```

### Adım 4: Python Parser Script

```bash
sudo nano /usr/local/bin/qradar_execve_parser.py
```

Parser script'i ekleyin:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar EXECVE Log Parser
"""
import sys
import re
import signal

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        
        self.args_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.cleanup_patterns = [
            re.compile(r'a\d+="[^"]*"\s*'),
            re.compile(r'argc=\d+\s*')
        ]

    def _signal_handler(self, signum, frame):
        sys.exit(0)

    def process_execve_line(self, line):
        if "type=EXECVE" not in line:
            return line

        if "proctitle=" in line or "PROCTITLE" in line:
            return None

        try:
            args_matches = self.args_pattern.findall(line)
            
            if not args_matches:
                return line

            args_dict = {int(index): value for index, value in args_matches}
            sorted_args = sorted(args_dict.items())
            combined_command = " ".join(arg[1] for arg in sorted_args)

            cleaned_line = line
            for pattern in self.cleanup_patterns:
                cleaned_line = pattern.sub('', cleaned_line)
            cleaned_line = cleaned_line.strip()

            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line

        except Exception:
            return line

    def run(self):
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                    
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line)
                        sys.stdout.flush()
                        
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
```

Script'i executable yapın:
```bash
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
```

### Adım 5: Rsyslog QRadar Konfigürasyonu

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

**ÖNEMLİ**: `<QRADAR_IP>` ve `<QRADAR_PORT>` değerlerini değiştirin:

```bash
# QRadar Log Forwarding Konfigürasyonu
module(load="omprog")

# QRadar template
template(name="QRadarFormat" type="string"
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\n")

# Local3 facility işleme
if $syslogfacility-text == 'local3' then {

    # EXECVE parser
    if $msg contains 'type=EXECVE' then {
        action(
            type="omprog"
            binary="/usr/local/bin/qradar_execve_parser.py"
            template="RSYSLOG_TraditionalFileFormat"
            queue.workerThreads="1"
        )
    }
    
    # QRadar'a TCP ile gönder
    action(
        type="omfwd"
        target="192.168.1.100"    # QRadar IP'nizi yazın
        port="514"                # QRadar portunu yazın
        protocol="tcp"
        template="QRadarFormat"
        
        queue.type="linkedlist"
        queue.size="10000"
        action.resumeRetryCount="5"
        action.resumeInterval="30"
    )

    stop
}
```

### Adım 6: Servisleri Başlatma

```bash
# Servisleri yeniden başlat
sudo systemctl restart auditd
sudo systemctl restart rsyslog

# Otomatik başlama
sudo systemctl enable auditd
sudo systemctl enable rsyslog
```

---

## RHEL/CentOS/Rocky/AlmaLinux Kurulum

### Adım 1: Paket Kurulumu

```bash
# RHEL 7/CentOS 7 için
sudo yum install -y audit audispd-plugins rsyslog python3

# RHEL 8+ için
sudo dnf install -y audit rsyslog python3

# Rocky Linux kontrolü
rpm -q rsyslog || sudo dnf install -y rsyslog
```

### Adım 2-5: Temel Konfigürasyonlar

Audit kuralları, Python parser ve rsyslog konfigürasyonu Debian/Ubuntu ile aynıdır.

**ÖNEMLİ FARK**: Audispd plugin yolu:

```bash
# RHEL 7/CentOS 7
sudo nano /etc/audisp/plugins.d/syslog.conf

# RHEL 8+
sudo nano /etc/audit/plugins.d/syslog.conf
```

### Adım 6: SELinux Konfigürasyonu

```bash
# SELinux durumu
getenforce

# SELinux aktifse:
sudo semanage fcontext -a -t bin_t "/usr/local/bin/qradar_execve_parser.py"
sudo restorecon -v /usr/local/bin/qradar_execve_parser.py
```

### Adım 7: Firewall Ayarları

```bash
# Firewall kontrolü
sudo systemctl status firewalld

# Gerekirse port açın
sudo firewall-cmd --permanent --add-port=514/tcp
sudo firewall-cmd --reload
```

### Adım 8: Servisleri Başlatma

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
sudo systemctl enable auditd
sudo systemctl enable rsyslog
```

---

## Kurulum Doğrulaması

### Test Adımları

```bash
# 1. Rsyslog konfigürasyon kontrolü
sudo rsyslogd -N1

# 2. Audit kuralları kontrolü
sudo auditctl -l

# 3. Parser script testi
echo 'type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | \
sudo /usr/local/bin/qradar_execve_parser.py

# 4. Test log gönderme
logger -p local3.info "QRadar Test Message"

# 5. QRadar bağlantı kontrolü
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -n
```

### Beklenen Sonuçlar

- Rsyslog konfigürasyonu syntax hatası vermemeli
- Audit kuralları listelenebilmeli
- Parser test'i komutu birleştirmeli
- Network trafiği görünmeli

---

## Temel Sorun Giderme

### Servis Kontrolleri

```bash
# Servis durumları
sudo systemctl status auditd
sudo systemctl status rsyslog

# Log kontrolleri
sudo journalctl -u auditd -n 20
sudo journalctl -u rsyslog -n 20
```

### Yaygın Sorunlar

**1. Audit kuralları yüklenmiyor:**
```bash
sudo auditctl -D  # Kuralları temizle
sudo auditctl -R /etc/audit/rules.d/99-qradar.rules  # Manuel yükle
```

**2. QRadar'a bağlantı yok:**
```bash
telnet <QRADAR_IP> <QRADAR_PORT>  # Bağlantı testi
```

**3. SELinux denial (RHEL):**
```bash
sudo ausearch -m avc -ts recent  # Denial'ları kontrol et
```

**4. Parser çalışmıyor:**
```bash
# İzin kontrolü
ls -la /usr/local/bin/qradar_execve_parser.py

# Manuel test
python3 /usr/local/bin/qradar_execve_parser.py
```

### Log Kontrolleri

```bash
# Audit logları
sudo tail -f /var/log/audit/audit.log

# Rsyslog mesajları
sudo tail -f /var/log/messages | grep local3

# QRadar'a giden loglar
sudo tail -f /var/log/messages | grep QRadar
```

---

## Güvenlik Notları

### Önemli Güvenlik Hususları

1. **TCP Protokolü**: UDP yerine TCP kullanın (güvenilirlik)
2. **Dosya İzinleri**: Konfigürasyon dosyalarını koruyun
3. **SELinux**: RHEL sistemlerde aktif tutun
4. **Firewall**: Sadece gerekli portları açın

### Dosya İzinleri

```bash
# Konfigürasyon dosyaları
sudo chmod 640 /etc/audit/rules.d/99-qradar.rules
sudo chmod 640 /etc/rsyslog.d/99-qradar.conf

# Parser script
sudo chmod 755 /usr/local/bin/qradar_execve_parser.py
sudo chown root:root /usr/local/bin/qradar_execve_parser.py
```

### Network Güvenliği

```bash
# TLS kullanımı önerilir (üretim ortamı için)
# Port 6514 TLS encrypted syslog için kullanılabilir
```

---

## Sonuç

Bu rehber ile Linux sistemlerinizden QRadar'a güvenli ve güvenilir log forwarding kurulumu tamamlanmıştır. Kurulum sonrası:

1. QRadar'da log source'unuzu konfigüre edin
2. Gelen logları kontrol edin
3. Düzenli olarak bağlantı durumunu izleyin
4. Gerektiğinde log volume'üne göre queue ayarlarını düzenleyin

**Destek**: Kurulum ile ilgili teknik sorularınız için lütfen iletişime geçin.

---

**Doküman Versiyonu**: 1.0  
**Son Güncelleme**: 2025  
**Platform Uyumluluğu**: Debian/Ubuntu, RHEL/CentOS/Rocky/AlmaLinux
