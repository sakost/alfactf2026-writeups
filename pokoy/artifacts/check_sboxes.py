#!/usr/bin/env python3
"""Check whether M_00000..M_00015 are SBOX[i] ^ k_i for a single SBOX
   (i.e., the per-byte difference is constant)."""
import json
from pathlib import Path

roms = json.loads(Path("./roms.json").read_text())

def get(rid):
    e = roms[str(rid)]
    if isinstance(e, dict):
        max_idx = max(int(k) for k in e)
        arr = [0] * (max_idx + 1)
        for k, v in e.items():
            arr[int(k)] = v
        return arr
    return e

sboxes = [get(i) for i in range(16)]

# Are M_00001[i] ^ M_00000[i] constant for all i?
for j in range(1, 16):
    diffs = set(sboxes[j][i] ^ sboxes[0][i] for i in range(256))
    print(f"M_{j:05d} ^ M_00000 distinct={len(diffs)}: {sorted(diffs)[:5]}")
