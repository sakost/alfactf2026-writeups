# Pokoy / Peace — alfaCTF 2026

**Category:** Reverse / Hardware  
**Difficulty:** Hard  
**Tags:** reverse, hardware, verilog, cocotb, aes, white-box-crypto  
**Flag:** `alfa{whitebox_means_open_floor_plan_3f16ce7b86f56a86f645c24e4b1}`

## Overview

We're given a Yosys-synthesised Verilog netlist (`peace.v`, ~58k lines) and a Python cocotb testbench (`peace.py`) that simulates a hardware device with a 4×4 keypad and a 128×64 pixel display. The device shows 64 hex bytes on the display. Someone typed the flag on the keypad and the screen displayed a specific 64-byte output. We have to recover what was typed.

## Stage 1 — Understanding the simulation

The `peace.py` script drives a cocotb simulation of the Verilog design. The display is 128×64 pixels rendered with Unicode block characters. A 4×4 keypad (keys `1-9`, `0`, `*`, `#`, `A-D`) feeds 4-bit codes into the hardware.

Key observations from `peace.py`:

- `COMMIT_CYCLES = HZ // 2 + 4 + 64 + 30` — after typing stops, the hardware runs an internal pipeline before output stabilises.
- The display is scanned row-by-row via `scan_pixels` to read 128-bit rows.

## Stage 2 — Identifying internal state

By running the simulation and probing internal memories, we identified several key structures:

| Memory | Size | Role |
|--------|------|------|
| `_M_00000_`..`_M_00015_` | 16 × 256 × 8-bit | Final-round S-boxes |
| `_M_00016_`..`_M_00159_` | 144 × 256 × 32-bit | T-tables (9 rounds × 16 lookups) |
| `_M_00160_`, `_M_00161_` | 64 × 8-bit each | Display byte buffer (runtime) |
| `_M_00324_` | 4 × 128-bit | Intermediate cipher state |
| `_M_00325_` | 4 × 128-bit | Final cipher output (4 blocks) |

The display reads `_M_00161_`, which holds the byte-reversed contents of `_M_00325_`. Each 128-bit slot = 16 bytes = 32 hex chars on screen. Four slots = 64 displayed bytes.

## Stage 3 — Recognising AES

The structure of 144 T-tables (9 rounds × 16 per round) + 16 byte S-boxes (final round) strongly suggests **AES-128** with 10 rounds (9 T-table rounds + 1 final SubBytes-only round).

We verified this by checking whether the 16 final-round S-boxes `M_00000..M_00015` have the form:

```
M_j[i] = AES_SBOX[i ⊕ a_j] ⊕ b_j
```

for some constants `(a_j, b_j)`. All 16 matched perfectly with the **standard AES S-box**. The pre-XOR values `a_j` correspond to round-9 key bytes; the post-XOR values `b_j` to round-10 key bytes.

Similarly, the 144 wide T-tables `M_00016..M_00159` matched the standard AES T-tables `T0..T3` with per-position key-XOR constants.

## Stage 4 — Extracting the AES key

From the round-1 T-tables (`M_00016..M_00031`), the pre-XOR `a` values give the **master key** (RK0) at each input-byte position. We mapped each ROM to its input byte using the Verilog `assign` statements:

```
M_00016 → byte 0  (a=0x3d)    M_00024 → byte 2  (a=0x73)
M_00017 → byte 1  (a=0x2e)    M_00025 → byte 3  (a=0x73)
M_00018 → byte 10 (a=0x0f)    M_00026 → byte 4  (a=0x0d)
M_00019 → byte 11 (a=0xe3)    M_00027 → byte 5  (a=0xed)
M_00020 → byte 12 (a=0xb8)    M_00028 → byte 6  (a=0x60)
M_00021 → byte 13 (a=0x3b)    M_00029 → byte 7  (a=0xec)
M_00022 → byte 14 (a=0x15)    M_00030 → byte 8  (a=0x44)
M_00023 → byte 15 (a=0x72)    M_00031 → byte 9  (a=0x75)
```

**Master key:** `3d 2e 73 73 0d ed 60 ec 44 75 0f e3 b8 3b 15 72`

## Stage 5 — Decrypting the flag

The 64 displayed hex bytes from the task form 4 AES blocks. Each displayed block is the byte-reversed ciphertext stored in `_M_00325_`. The plaintext bytes are also stored in reverse order relative to the typed string.

Decryption procedure for each block:

1. Take the 16 displayed bytes.
2. Reverse byte order → `_M_00325_` ciphertext.
3. AES-128-ECB decrypt with the master key.
4. Reverse byte order → original typed characters.

```
Block 0: "alfa{whitebox_me"
Block 1: "ans_open_floor_p"
Block 2: "lan_3f16ce7b86f5"
Block 3: "6a86f645c24e4b1}"
```

## Flag

`alfa{whitebox_means_open_floor_plan_3f16ce7b86f56a86f645c24e4b1}`

The flag references **white-box cryptography** — an AES implementation where the key is embedded directly into lookup tables, making it "visible" (like an open floor plan in a coworking space — the literal meaning of «Покой», the challenge name).

## Key Takeaways

- Synthesised hardware netlists are an excellent target for AES recovery: the well-known structure (144 T-tables + 16 final S-boxes) is preserved through synthesis, and the per-position `a_j ⊕ S[i] ⊕ b_j` identity directly hands you `RK_9` and `RK_10` byte by byte. From the last two round keys the master key falls out via the AES key schedule (or, here, more directly from round-1 tables).
- "White-box" only means the key is hidden inside table contents, not inside a register — once you can probe ROM contents, those tables *are* the key. This challenge is a textbook reduction of white-box AES to plain AES.
- When working with synthesised designs, the byte-order of memory contents vs. the byte-order of the rendered display vs. the byte-order of the typed input can each be reversed independently. Always confirm the direction empirically with one known plaintext-ciphertext pair before trusting a recovered key.
