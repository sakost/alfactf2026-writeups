#!/usr/bin/env python3
"""Extract all _M_xxxxx_ ROM initial blocks from the peace.v netlist.

The peace.v netlist (~58k lines) is the original challenge file and is NOT
included in this repo. Pass its path as the first argument, or place it at
./peace.v.
"""
import re
import json
import sys
from pathlib import Path

src_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./peace.v")
src = src_path.read_text()

# Pattern: \_M_xxxxx_ [N] = WIDTH'h|d|bVAL;
pat = re.compile(r"\\_M_(\d+)_\s+\[(\d+)\]\s*=\s*(\d+)'([hdb])([0-9a-fA-F]+);")

roms = {}
for m in pat.finditer(src):
    rom_id = int(m.group(1))
    idx = int(m.group(2))
    width = int(m.group(3))
    base = m.group(4)
    raw = m.group(5)
    if base == 'h':
        val = int(raw, 16)
    elif base == 'd':
        val = int(raw, 10)
    elif base == 'b':
        val = int(raw, 2)
    roms.setdefault(rom_id, {})[idx] = val

# convert to lists
out = {}
for rid, entries in roms.items():
    max_idx = max(entries)
    arr = [0] * (max_idx + 1)
    for k, v in entries.items():
        arr[k] = v
    out[rid] = arr

# also detect the M_00324 / 325 / 331 style (no \ prefix, regs not memories)
# These are still memories. Pattern is `_M_00324_[N] = ...`
# but they're declared as `reg [127:0] _M_00324_ [3:0];` — different syntax for init?
pat2 = re.compile(r"_M_(\d+)\s*\[(\d+)\]\s*=\s*(\d+)'h([0-9a-fA-F]+);")
for m in pat2.finditer(src):
    rom_id = int(m.group(1))
    idx = int(m.group(2))
    width = int(m.group(3))
    val = int(m.group(4), 16)
    if rom_id not in roms:
        roms[rom_id] = {}
    roms[rom_id][idx] = val

print(f"ROM count: {len(roms)}")
for rid in sorted(roms.keys()):
    e = roms[rid]
    nbytes = len(e)
    print(f"  M_{rid:05d}: {nbytes} entries, first 8: {[hex(e[i]) for i in sorted(e)[:8]]}")

# save to a JSON for further analysis
out_path = Path("./roms.json")
out_path.write_text(json.dumps({str(k): roms[k] for k in roms}, default=lambda o: o))
print(f"Saved to {out_path}")
