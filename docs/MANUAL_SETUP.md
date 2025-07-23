# Manual QRadar Log Forwarding Setup

This document provides instructions for manually configuring Linux systems to forward audit logs to IBM QRadar SIEM. These instructions are an alternative to using the provided installer scripts and have been verified against official documentation for rsyslog, auditd, and SELinux.

## Important Version Notes

- **Rsyslog Version**: Some parameters like `forceSingleInstance` require rsyslog v8.38.0 or later
- **RHEL 8+ Changes**: audispd functionality is integrated into auditd with path changes
- **Rocky Linux**: Minimal installations do NOT include rsyslog by default - manual installation required

## Introduction

The goal of this setup is to configure `auditd` to collect system audit events, `rsyslog` to forward these events to QRadar using **TCP (recommended over UDP)**, and a Python script to parse and format the logs for better readability and analysis in QRadar.

This guide is divided into two main sections:
*   **Debian/Ubuntu Setup**
*   **RHEL/CentOS/Rocky/AlmaLinux Setup**

Please follow the instructions for your specific distribution.

## Prerequisites

*   **Root Access**: You must have `sudo` or `root` privileges to complete these steps.
*   **QRadar Server**: You must have a QRadar server with a configured log source to receive the forwarded logs.
*   **Network Connectivity**: The system you are configuring must be able to reach the QRadar server on the specified IP address and port.
*   **Rsyslog Version Check**: Run `rsyslogd -v` to check your version (some features require v8.38.0+)

---

## Debian/Ubuntu Manual Setup

These instructions apply to Debian 9+ and Ubuntu 18.04+.

### 1. Install Prerequisites

First, update your package list and install the necessary packages:

```bash
sudo apt-get update
sudo apt-get install -y auditd audispd-plugins rsyslog python3
```

### 2. Configure Auditd Rules

Create a new audit rules file for QRadar:

```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
```

Copy and paste the following rules into the file:

```
# QRadar Audit Rules
-D
-b 16384
-f 1
-r 150
-i
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/pam.d/ -p wa -k authentication_config
-w /etc/security/ -p wa -k security_config
-w /etc/login.defs -p wa -k login_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S execve -k root_commands
-a always,exit -F arch=b32 -S execve -k root_commands
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/network/interfaces -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/netcat -p x -k network_tools
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
-w /usr/bin/rsync -p x -k remote_access
-w /usr/bin/whoami -p x -k system_discovery
-w /usr/bin/id -p x -k system_discovery
-w /usr/bin/w -p x -k system_discovery
-w /usr/bin/who -p x -k system_discovery
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services
-w /usr/lib/systemd/system/ -p wa -k systemd_services
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /var/log/auth.log -p wa -k log_modification
-w /var/log/syslog -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
-w /etc/audit/ -p wa -k audit_config
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
```

### 3. Configure Audispd to Forward to Syslog

Edit the `syslog.conf` file to enable forwarding of audit events to syslog:

```bash
# For Ubuntu 20.04+ and Debian 10+
sudo nano /etc/audit/plugins.d/syslog.conf

# For older versions
sudo nano /etc/audisp/plugins.d/syslog.conf
```

Ensure the file contains the following:

```
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
```

### 4. Deploy the Python Parser Script

Create the Python script to parse and format the `EXECVE` logs:

```bash
sudo nano /usr/local/bin/qradar_execve_parser.py
```

Copy and paste the following code into the file:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar EXECVE Log Parser for rsyslog omprog module
IMPORTANT: Uses readline() to avoid buffering issues with rsyslog
"""
import sys
import re
import signal

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        
        # Compile regex patterns for better performance
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

            # Clean up the original line
            cleaned_line = line
            for pattern in self.cleanup_patterns:
                cleaned_line = pattern.sub('', cleaned_line)
            cleaned_line = cleaned_line.strip()

            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line

        except Exception:
            return line

    def run(self):
        """
        Main processing loop using readline() to avoid buffering issues
        CRITICAL: Do NOT use 'for line in sys.stdin' with rsyslog omprog
        """
        try:
            while True:
                line = sys.stdin.readline()
                if not line:  # EOF
                    break
                    
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line)
                        sys.stdout.flush()  # Critical for omprog communication
                        
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
```

### 5. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
# Load required modules
module(load="omprog")

# QRadar-compatible template (RFC 3339 time stamp)
template(name="QRadarFormat" type="string"
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\n")

# Only process messages from facility local3
if $syslogfacility-text == 'local3' then {

    # Process EXECVE events with parser
    if $msg contains 'type=EXECVE' then {
        action(
            type="omprog"
            binary="/usr/local/bin/qradar_execve_parser.py"
            template="RSYSLOG_TraditionalFileFormat"
            # Note: forceSingleInstance requires rsyslog v8.38.0+
            # Uncomment if your version supports it:
            # forceSingleInstance="on"
            queue.workerThreads="1"
        )
    }
    
    # Forward all audit logs to QRadar using TCP (recommended)
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"  # Use TCP for reliable delivery
        template="QRadarFormat"
        
        # Reliable async queue with production-ready settings
        queue.type="linkedlist"
        queue.size="50000"
        queue.maxdiskspace="2g"
        queue.saveOnShutdown="on"
        queue.highWatermark="40000"
        queue.lowWatermark="10000"
        queue.discardMark="45000"
        queue.discardSeverity="4"
        action.resumeRetryCount="-1"  # Infinite retries for reliability
        action.resumeInterval="30"
    )

    stop    # Prevent further rule processing
}
```

### 6. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 7. Verify the Setup

Verify the configuration and test log forwarding:

```bash
# Check rsyslog version
rsyslogd -v

# Check rsyslog configuration syntax
sudo rsyslogd -N1

# Test the parser script
echo 'type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | sudo /usr/local/bin/qradar_execve_parser.py

# Send test logs
logger -p local3.info "Test QRadar forwarding"
logger -p local3.info 'type=EXECVE msg=audit(1234:567): argc=3 a0="test" a1="-la" a2="/tmp"'

# Monitor traffic to QRadar (should show TCP connection)
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```

---

## RHEL/CentOS/Rocky/AlmaLinux Manual Setup

These instructions apply to RHEL 7+, CentOS 7+, Rocky Linux, AlmaLinux, and other RHEL-based distributions.

### 1. Install Prerequisites

First, install the necessary packages using `yum` or `dnf`:

```bash
# For RHEL 7/CentOS 7
sudo yum install -y audit audispd-plugins rsyslog python3

# For RHEL 8+ and derivatives (Rocky Linux, AlmaLinux)
sudo dnf install -y audit rsyslog python3

# Note: Rocky Linux minimal installation requires rsyslog installation
# Verify rsyslog is installed:
rpm -q rsyslog || sudo dnf install -y rsyslog
```

### 2. Configure Auditd Rules

Create a new audit rules file for QRadar:

```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
```

Copy and paste the following rules into the file:

```
# QRadar Audit Rules
-D
-b 16384
-f 1
-r 150
-i
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/pam.d/ -p wa -k authentication_config
-w /etc/security/ -p wa -k security_config
-w /etc/login.defs -p wa -k login_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S execve -k root_commands
-a always,exit -F arch=b32 -S execve -k root_commands
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/sysconfig/network-scripts/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/netcat -p x -k network_tools
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
-w /usr/bin/rsync -p x -k remote_access
-w /usr/bin/whoami -p x -k system_discovery
-w /usr/bin/id -p x -k system_discovery
-w /usr/bin/w -p x -k system_discovery
-w /usr/bin/who -p x -k system_discovery
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services
-w /usr/lib/systemd/system/ -p wa -k systemd_services
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /var/log/messages -p wa -k log_modification
-w /var/log/secure -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
-w /etc/audit/ -p wa -k audit_config
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
```

### 3. Configure Audispd to Forward to Syslog

**Important**: The path differs based on RHEL version:

```bash
# For RHEL 7/CentOS 7
sudo nano /etc/audisp/plugins.d/syslog.conf

# For RHEL 8+ (including Rocky Linux, AlmaLinux)
# Note: audispd is integrated into auditd in RHEL 8+
sudo nano /etc/audit/plugins.d/syslog.conf
```

Ensure the file contains the following:

```
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
```

### 4. Deploy the Python Parser Script

Create the Python script to parse and format the `EXECVE` logs:

```bash
sudo nano /usr/local/bin/qradar_execve_parser.py
```

Copy and paste the following code into the file:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar EXECVE Log Parser for rsyslog omprog module
IMPORTANT: Uses readline() to avoid buffering issues with rsyslog
"""
import sys
import re
import signal

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        
        # Compile regex patterns for better performance
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

            # Clean up the original line
            cleaned_line = line
            for pattern in self.cleanup_patterns:
                cleaned_line = pattern.sub('', cleaned_line)
            cleaned_line = cleaned_line.strip()

            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line

        except Exception:
            return line

    def run(self):
        """
        Main processing loop using readline() to avoid buffering issues
        CRITICAL: Do NOT use 'for line in sys.stdin' with rsyslog omprog
        """
        try:
            while True:
                line = sys.stdin.readline()
                if not line:  # EOF
                    break
                    
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line)
                        sys.stdout.flush()  # Critical for omprog communication
                        
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
```

### 5. Configure SELinux

If SELinux is enabled on your system, configure the necessary permissions:

```bash
# Check SELinux status
getenforce

# If SELinux is enabled, proceed with the following:

# Set proper context for the Python script
sudo semanage fcontext -a -t bin_t "/usr/local/bin/qradar_execve_parser.py"
sudo restorecon -v /usr/local/bin/qradar_execve_parser.py

# IMPORTANT: rsyslog_can_network_connect boolean does NOT exist
# Instead, ensure rsyslog can connect to syslog ports
sudo semanage port -l | grep syslog
# If your QRadar port is not in the syslog_port_t list, add it:
# sudo semanage port -a -t syslogd_port_t -p tcp <QRADAR_PORT>

# Allow rsyslog to execute external programs (if needed)
# Check for denials first
sudo ausearch -c 'rsyslogd' --raw | audit2allow -M my-rsyslogd
# Review the generated policy before applying
sudo cat my-rsyslogd.te
# Apply only if necessary
sudo semodule -i my-rsyslogd.pp

# Alternative: If you encounter issues, you can temporarily set permissive mode for rsyslog
# sudo semanage permissive -a rsyslogd_t
# Note: This is less secure and should only be used for troubleshooting
```

### 6. Configure FirewallD

If FirewallD is enabled, configure it to allow outbound traffic to QRadar:

```bash
# Check if firewalld is running
sudo systemctl status firewalld

# Most environments allow outbound traffic by default
# If you need to explicitly allow it:
sudo firewall-cmd --permanent --add-port=<QRADAR_PORT>/tcp
sudo firewall-cmd --reload

# Verify the rule
sudo firewall-cmd --list-all
```

### 7. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
# Load required modules
module(load="omprog")

# QRadar-compatible template (RFC 3339 time stamp)
template(name="QRadarFormat" type="string"
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\n")

# Only process messages from facility local3
if $syslogfacility-text == 'local3' then {

    # Process EXECVE events with parser
    if $msg contains 'type=EXECVE' then {
        action(
            type="omprog"
            binary="/usr/local/bin/qradar_execve_parser.py"
            template="RSYSLOG_TraditionalFileFormat"
            # Note: forceSingleInstance requires rsyslog v8.38.0+
            # Uncomment if your version supports it:
            # forceSingleInstance="on"
            queue.workerThreads="1"
        )
    }
    
    # Forward all audit logs to QRadar using TCP (recommended)
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"  # Use TCP for reliable delivery
        template="QRadarFormat"
        
        # Reliable async queue with production-ready settings
        queue.type="linkedlist"
        queue.size="50000"
        queue.maxdiskspace="2g"
        queue.saveOnShutdown="on"
        queue.highWatermark="40000"
        queue.lowWatermark="10000"
        queue.discardMark="45000"
        queue.discardSeverity="4"
        action.resumeRetryCount="-1"  # Infinite retries for reliability
        action.resumeInterval="30"
    )

    stop    # Prevent further rule processing
}
```

### 8. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 9. Verify the Setup

Verify the configuration and test log forwarding:

```bash
# Check rsyslog version
rsyslogd -v

# Check rsyslog configuration syntax
sudo rsyslogd -N1

# Test the parser script
echo 'type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | sudo /usr/local/bin/qradar_execve_parser.py

# Send test logs
logger -p local3.info "Test QRadar forwarding"
logger -p local3.info 'type=EXECVE msg=audit(1234:567): argc=3 a0="test" a1="-la" a2="/tmp"'

# Monitor traffic to QRadar (should show TCP connection)
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n

# Check for SELinux denials
sudo ausearch -m avc -ts recent
```

## Troubleshooting

### Check Service Status
```bash
# Check auditd status
sudo systemctl status auditd

# Check rsyslog status
sudo systemctl status rsyslog

# View rsyslog errors
sudo journalctl -u rsyslog -f

# Check audit daemon logs
sudo ausearch -m daemon_start -ts recent
```

### Debug Rsyslog Configuration
```bash
# Run rsyslog in debug mode
sudo rsyslogd -dn 2>&1 | grep -i "qradar\|omprog\|omfwd\|local3"

# Check rsyslog statistics
sudo pkill -USR1 rsyslogd && sudo tail -f /var/log/messages | grep rsyslogd-pstats

# Verify rsyslog is receiving audit logs
sudo tail -f /var/log/messages | grep local3
```

### Common Issues and Solutions

1. **SELinux Denials**: 
   - Check `/var/log/audit/audit.log` for denials
   - Use `audit2allow` to create custom policies only if needed
   - Remember: `rsyslog_can_network_connect` boolean does NOT exist

2. **Network Connectivity**: 
   - Ensure TCP connectivity to QRadar: `telnet <QRADAR_IP> <QRADAR_PORT>`
   - Check for firewall blocks: `sudo iptables -L -n | grep <QRADAR_PORT>`

3. **Parser Errors**: 
   - Test the parser script manually with sample EXECVE logs
   - Ensure Python script uses `readline()` not `for line in sys.stdin`
   - Check script has executable permissions

4. **Queue Overflow**: 
   - Monitor queue statistics in rsyslog stats
   - Adjust queue sizes based on your log volume
   - Consider disk-assisted queues for very high volumes

5. **RHEL 8+ audispd Path**: 
   - Remember the path change from `/etc/audisp/` to `/etc/audit/plugins.d/`
   - Verify correct path exists before editing

## Performance Tuning

For high-volume environments, consider these optimizations:

### Audit Buffer Size
```bash
# In /etc/audit/rules.d/99-qradar.rules, increase buffer size:
-b 32768  # or higher for very busy systems (max: 65536)
```

### Rsyslog Global Settings
```bash
# Add to /etc/rsyslog.conf:
global(
    maxMessageSize="64k"
    workDirectory="/var/spool/rsyslog"
)

# Or legacy format:
$MaxMessageSize 64k
$WorkDirectory /var/spool/rsyslog
```

### Disk-Assisted Queues for High Volume
```bash
# Modify the queue configuration in 99-qradar.conf:
queue.type="linkedlist"
queue.filename="qradar_queue"  # Enables disk assistance
queue.maxdiskspace="5g"
queue.highwatermark="500000"
queue.lowwatermark="200000"
```

### Log Rotation
```bash
# Create /etc/logrotate.d/qradar-audit:
/var/log/audit/audit.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/pkill -HUP rsyslogd > /dev/null 2>&1 || true
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
```

## Network Protocol Recommendation

**Always use TCP instead of UDP for QRadar log forwarding:**
- TCP ensures reliable delivery with acknowledgments
- UDP can result in log loss during network congestion
- QRadar handles TCP connections efficiently
- Use `protocol="tcp"` in the omfwd action

## Version-Specific Notes

### Rsyslog Versions
- **v8.38.0+**: Supports `forceSingleInstance` parameter
- **v8.30.0+**: Improved default queue sizes
- **v7.x**: May require different module loading syntax

### Distribution Differences
- **RHEL 8+**: audispd integrated into auditd, different plugin path
- **Rocky Linux**: Minimal install doesn't include rsyslog
- **Ubuntu 20.04+**: Uses `/etc/audit/plugins.d/` path
- **Debian 9**: Uses older `/etc/audisp/plugins.d/` path

## Security Considerations

1. **Use TCP with Encryption**: Consider TLS for sensitive environments
2. **Limit Parser Permissions**: Run with minimal required privileges
3. **Monitor Queue Sizes**: Prevent DoS through queue exhaustion
4. **Regular Updates**: Keep rsyslog and audit packages updated
5. **Access Control**: Restrict access to audit rules and configuration files

## Final Notes

- The Python parser script formats EXECVE logs for better readability in QRadar
- All audit events are forwarded to QRadar, with EXECVE events being pre-processed
- The configuration uses reliable queuing to prevent log loss during network issues
- TCP protocol is strongly recommended over UDP for reliability
- Adjust queue parameters based on your environment's log volume and network reliability
- Test thoroughly in a non-production environment before deploying
