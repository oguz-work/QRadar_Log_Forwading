# Ubuntu 22.04 Auditd Configuration for QRadar SIEM
## MITRE ATT&CK Uyumlu Basit Konfigürasyon Dökümanı

### 1. Auditd Kurulumu ve Temel Yapılandırma

```bash
# Auditd kurulumu
sudo apt update
sudo apt install auditd audispd-plugins -y

# Servisi etkinleştir
sudo systemctl enable auditd
sudo systemctl start auditd
```

### 2. Ana Audit Rules Dosyası (/etc/audit/rules.d/qradar.rules)

Aşağıdaki içeriği `/etc/audit/rules.d/qradar.rules` dosyasına kaydedin:

```bash
# QRadar SIEM için Optimize Edilmiş Audit Rules
# MITRE ATT&CK Coverage: T1059, T1003, T1055, T1070, T1078, T1098, T1136, T1543

# Buffer ve performans ayarları
-b 8192
-f 1
--backlog_wait_time 60000

# Önceki kuralları temizle
-D

# Sistem çağrıları için arch tanımlaması
-a always,exit -F arch=b64 -S execve -F success=1 -F key=command_execution
-a always,exit -F arch=b32 -S execve -F success=1 -F key=command_execution

# Tüm komutlar için a0 field'ını yakala (Command Execution - T1059)
-a always,exit -F arch=b64 -S execve -F a0 -F key=user_commands
-a always,exit -F arch=b32 -S execve -F a0 -F key=user_commands

# Sudo ve su komutları (Privilege Escalation - T1078)
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sudo -F key=privilege_escalation
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/su -F key=privilege_escalation

# Kullanıcı ve grup yönetimi (Account Manipulation - T1098, T1136)
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/shadow -p wa -k password_change
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# SSH ve uzak bağlantılar (Remote Services - T1021)
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k ssh_keys -F path=/home/*/.ssh/

# Kritik binary değişiklikleri (Persistence - T1543)
-w /usr/bin/ -p wa -k binary_modification
-w /usr/sbin/ -p wa -k binary_modification
-w /bin/ -p wa -k binary_modification
-w /sbin/ -p wa -k binary_modification

# Log temizleme girişimleri (Defense Evasion - T1070)
-w /var/log/ -p wa -k log_modification
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F key=file_deletion
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F key=file_deletion

# Network konfigürasyonları (Discovery - T1016)
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

# Cron job değişiklikleri (Persistence - T1053)
-w /etc/cron.d/ -p wa -k cron_modification
-w /etc/crontab -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k user_cron

# Kernel modül yükleme (Persistence - T1547)
-a always,exit -F arch=b64 -S init_module,finit_module -F key=kernel_module
-a always,exit -F arch=b32 -S init_module,finit_module -F key=kernel_module

# Bellek erişim girişimleri (Credential Dumping - T1003)
-a always,exit -F arch=b64 -S ptrace -F key=process_injection
-a always,exit -F arch=b32 -S ptrace -F key=process_injection
-w /proc/kcore -p wa -k memory_dump
-w /dev/mem -p wa -k memory_dump

# Dosya bütünlüğü için kritik sistem dosyaları
-w /etc/ld.so.conf -p wa -k library_configuration
-w /etc/ld.so.conf.d/ -p wa -k library_configuration

# Make the configuration immutable
-e 2
```

### 3. Auditd.conf Optimizasyonu (/etc/audit/auditd.conf)

Aşağıdaki parametreleri `/etc/audit/auditd.conf` dosyasında güncelleyin:

```bash
# Log dosyası konumu
log_file = /var/log/audit/audit.log

# Performans ayarları
max_log_file = 50
max_log_file_action = ROTATE
num_logs = 5

# Buffer ayarları
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50

# Format (QRadar için enriched format)
log_format = ENRICHED
```

### 4. QRadar Syslog İletimi Konfigürasyonu

`/etc/audit/plugins.d/syslog.conf` dosyasını düzenleyin:

```bash
# QRadar'a syslog gönderimi
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
```

### 5. Rsyslog Konfigürasyonu (/etc/rsyslog.d/60-auditd.conf)

```bash
# Auditd loglarını QRadar'a gönder
# QRadar IP adresini kendi ortamınıza göre değiştirin

# Audit logları için template
template(name="AuditFormat" type="string" 
  string="<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n")

# Local6 facility'yi dinle ve QRadar'a forward et
local6.*    @@QRADAR_IP:514;AuditFormat

# Gereksiz sistem mesajlarını filtrele
:msg, contains, "systemd" stop
:msg, contains, "kernel: audit" stop
:msg, contains, "NetworkManager" stop
:msg, contains, "snapd" stop
```

### 6. Filtreleme ve Gürültü Azaltma

`/etc/audit/rules.d/filter.rules` dosyası oluşturun:

```bash
# Gereksiz sistem daemon'larını filtrele
-a never,exit -F exe=/usr/lib/systemd/systemd
-a never,exit -F exe=/usr/bin/dbus-daemon
-a never,exit -F exe=/usr/sbin/NetworkManager
-a never,exit -F exe=/snap/snapd/current/usr/lib/snapd/snapd
-a never,exit -F exe=/usr/lib/accountsservice/accounts-daemon
-a never,exit -F exe=/usr/sbin/cron
```

### 7. Uygulama ve Test

```bash
# Kuralları yükle
sudo augenrules --load

# Audit daemon'ı yeniden başlat
sudo systemctl restart auditd

# Rsyslog'u yeniden başlat
sudo systemctl restart rsyslog

# Kuralları kontrol et
sudo auditctl -l

# Test komutu çalıştır
sudo echo "Test command for QRadar"

# Log kontrolü
sudo ausearch -k user_commands --format text | tail -10
```

### 8. QRadar DSM Konfigürasyonu

QRadar tarafında Ubuntu 22.04 için DSM ayarları:

1. **Log Source Type**: Linux OS
2. **Protocol**: Syslog
3. **Event Format**: LEEF veya CEF
4. **Port**: 514 (TCP/UDP)

### 9. Performans İzleme

```bash
# Audit performans durumu
sudo auditctl -s

# Buffer kullanımı
sudo aureport --summary

# Kayıp event kontrolü
sudo aureport --anomaly
```

### 10. Troubleshooting

```bash
# Audit servis durumu
sudo systemctl status auditd

# Son audit logları
sudo journalctl -u auditd -n 50

# Syslog iletim kontrolü
sudo tcpdump -i any -n port 514 -c 10

# Audit log format kontrolü
sudo tail -f /var/log/audit/audit.log | grep -E "type=EXECVE|type=USER_CMD"
```

## Önemli Notlar

1. **a0 Field'ı**: Tüm execve sistem çağrılarında a0 parametresi (komut argümanı) yakalanır
2. **MITRE Coverage**: T1059, T1003, T1055, T1070, T1078, T1098, T1136, T1543 tekniklerini kapsar
3. **Performance**: Buffer boyutu ve async flush ile optimize edilmiştir
4. **Filtreleme**: Gereksiz sistem daemon mesajları filtrelenir
5. **QRadar Uyumu**: LEEF/CEF formatında enriched loglar gönderilir

## Güvenlik Önerileri

- Audit loglarını düzenli olarak arşivleyin
- Log rotation'ı aktif tutun
- Audit kurallarını immutable (-e 2) yapın
- QRadar bağlantısını TLS ile şifreleyin (@@@ kullanarak)
- Düzenli olarak aureport ile anomali kontrolü yapın