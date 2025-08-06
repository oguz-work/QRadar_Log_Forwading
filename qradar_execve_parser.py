#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar EXECVE Log Parser
Audit EXECVE loglarını QRadar için optimize edilmiş formata dönüştürür
"""
import sys
import re
import signal
import json
from datetime import datetime

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        
        # Pattern tanımlamaları
        self.args_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.field_pattern = re.compile(r'(\w+)=([^\s]+)')
        self.quoted_field_pattern = re.compile(r'(\w+)="([^"]*)"')
        self.cleanup_patterns = [
            re.compile(r'a\d+="[^"]*"\s*'),
            re.compile(r'argc=\d+\s*')
        ]

    def _signal_handler(self, signum, frame):
        sys.exit(0)

    def extract_fields(self, line):
        """Log satırından tüm alanları çıkarır"""
        fields = {}
        
        # Önce tırnak içindeki alanları bul
        for match in self.quoted_field_pattern.finditer(line):
            fields[match.group(1)] = match.group(2)
        
        # Sonra tırnaksız alanları bul
        temp_line = self.quoted_field_pattern.sub('', line)
        for match in self.field_pattern.finditer(temp_line):
            if match.group(1) not in fields:
                fields[match.group(1)] = match.group(2)
        
        return fields

    def process_execve_line(self, line):
        if "type=EXECVE" not in line:
            return line

        # PROCTITLE loglarını filtrele
        if "proctitle=" in line or "PROCTITLE" in line:
            return None

        try:
            # Tüm alanları çıkar
            fields = self.extract_fields(line)
            
            # Argümanları topla ve birleştir
            args_matches = self.args_pattern.findall(line)
            
            if not args_matches:
                return line

            args_dict = {int(index): value for index, value in args_matches}
            sorted_args = sorted(args_dict.items())
            combined_command = " ".join(arg[1] for arg in sorted_args)

            # Orijinal satırı temizle
            cleaned_line = line
            for pattern in self.cleanup_patterns:
                cleaned_line = pattern.sub('', cleaned_line)
            cleaned_line = cleaned_line.strip()

            # QRadar için özel alanlar ekle
            qradar_fields = []
            
            # Komut alanı
            qradar_fields.append(f'cmd="{combined_command}"')
            
            # Kullanıcı bilgileri
            if 'uid' in fields:
                qradar_fields.append(f'uid={fields["uid"]}')
            if 'auid' in fields:
                qradar_fields.append(f'auid={fields["auid"]}')
            if 'ses' in fields:
                qradar_fields.append(f'ses={fields["ses"]}')
            
            # İşlem bilgileri
            if 'pid' in fields:
                qradar_fields.append(f'pid={fields["pid"]}')
            if 'ppid' in fields:
                qradar_fields.append(f'ppid={fields["ppid"]}')
            
            # Terminal bilgisi
            if 'terminal' in fields:
                qradar_fields.append(f'terminal={fields["terminal"]}')
            
            # Executable path
            if 'exe' in fields:
                qradar_fields.append(f'exe="{fields["exe"]}"')
            
            # Key değeri (varsa)
            if 'key' in fields:
                qradar_fields.append(f'key="{fields["key"]}"')

            # İşlenmiş satırı oluştur
            processed_line = f"{cleaned_line} {' '.join(qradar_fields)}"
            return processed_line

        except Exception as e:
            # Hata durumunda orijinal satırı döndür
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
