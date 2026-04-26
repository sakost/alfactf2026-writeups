#!/usr/bin/env python3
"""Standard AES-128 implementation. Decrypt the empty ciphertext (and the
   target ciphertexts) with the master key recovered from M_00016..M_00031."""

AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0]*256
for i,v in enumerate(AES_SBOX): INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def expand_key(key):
    """Return RK0..RK10 as 16-byte arrays."""
    rk = [list(key[:16])]
    for r in range(10):
        prev = rk[-1]
        new = [0]*16
        # word 0
        t = [prev[12+1], prev[12+2], prev[12+3], prev[12+0]]  # rotate
        t = [AES_SBOX[b] for b in t]
        t[0] ^= RCON[r]
        for i in range(4):
            new[i] = prev[i] ^ t[i]
        # words 1-3
        for w in range(1, 4):
            for i in range(4):
                new[w*4+i] = prev[w*4+i] ^ new[(w-1)*4+i]
        rk.append(new)
    return rk

def aes_encrypt(plaintext, key):
    """Encrypt 16-byte plaintext with 16-byte key."""
    rks = expand_key(key)
    state = [plaintext[i] ^ rks[0][i] for i in range(16)]
    for r in range(1, 10):
        # SubBytes
        state = [AES_SBOX[b] for b in state]
        # ShiftRows: state[r, c] = state[r, (c+r) mod 4] = byte at row r, col (c+r)%4
        # In our layout state[r*4+c] but it's easier to think column-major.
        # AES standard layout: state[c*4+r] for column c, row r (column-major).
        # Let me use the column-major convention.
        # Actually let's use standard convention: state stored row-major: byte[i] at row i%4, col i/4 ... NOPE this is getting confusing.
        # Use 4x4 grid:
        s = [[state[c*4+r] for c in range(4)] for r in range(4)]
        s = [[s[r][(c+r) % 4] for c in range(4)] for r in range(4)]
        # MixColumns
        new_s = [[0]*4 for _ in range(4)]
        for c in range(4):
            col = [s[r][c] for r in range(4)]
            new_col = [
                gmul(2,col[0]) ^ gmul(3,col[1]) ^ col[2] ^ col[3],
                col[0] ^ gmul(2,col[1]) ^ gmul(3,col[2]) ^ col[3],
                col[0] ^ col[1] ^ gmul(2,col[2]) ^ gmul(3,col[3]),
                gmul(3,col[0]) ^ col[1] ^ col[2] ^ gmul(2,col[3]),
            ]
            for r in range(4):
                new_s[r][c] = new_col[r]
        # back to flat state, column-major
        state = [new_s[r][c] for c in range(4) for r in range(4)]
        # AddRoundKey
        state = [state[i] ^ rks[r][i] for i in range(16)]
    # Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    state = [AES_SBOX[b] for b in state]
    s = [[state[c*4+r] for c in range(4)] for r in range(4)]
    s = [[s[r][(c+r) % 4] for c in range(4)] for r in range(4)]
    state = [s[r][c] for c in range(4) for r in range(4)]
    state = [state[i] ^ rks[10][i] for i in range(16)]
    return bytes(state)


def aes_decrypt(ct, key):
    """Decrypt 16-byte ct with 16-byte key."""
    rks = expand_key(key)
    state = [ct[i] ^ rks[10][i] for i in range(16)]
    # Inverse final round: undo ShiftRows, undo SubBytes
    s = [[state[c*4+r] for c in range(4)] for r in range(4)]
    s = [[s[r][(c-r) % 4] for c in range(4)] for r in range(4)]
    state = [s[r][c] for c in range(4) for r in range(4)]
    state = [INV_SBOX[b] for b in state]
    for r in range(9, 0, -1):
        state = [state[i] ^ rks[r][i] for i in range(16)]
        # InverseMixColumns
        s = [[state[c*4+r2] for c in range(4)] for r2 in range(4)]
        new_s = [[0]*4 for _ in range(4)]
        for c in range(4):
            col = [s[r2][c] for r2 in range(4)]
            new_col = [
                gmul(0x0e,col[0]) ^ gmul(0x0b,col[1]) ^ gmul(0x0d,col[2]) ^ gmul(0x09,col[3]),
                gmul(0x09,col[0]) ^ gmul(0x0e,col[1]) ^ gmul(0x0b,col[2]) ^ gmul(0x0d,col[3]),
                gmul(0x0d,col[0]) ^ gmul(0x09,col[1]) ^ gmul(0x0e,col[2]) ^ gmul(0x0b,col[3]),
                gmul(0x0b,col[0]) ^ gmul(0x0d,col[1]) ^ gmul(0x09,col[2]) ^ gmul(0x0e,col[3]),
            ]
            for r2 in range(4):
                new_s[r2][c] = new_col[r2]
        state = [new_s[r2][c] for c in range(4) for r2 in range(4)]
        # InverseShiftRows
        s = [[state[c*4+r2] for c in range(4)] for r2 in range(4)]
        s = [[s[r2][(c-r2) % 4] for c in range(4)] for r2 in range(4)]
        state = [s[r2][c] for c in range(4) for r2 in range(4)]
        # InverseSubBytes
        state = [INV_SBOX[b] for b in state]
    state = [state[i] ^ rks[0][i] for i in range(16)]
    return bytes(state)


# Master key derived from a values of round-1 T-tables
RK0 = bytes([0x3d, 0x2e, 0x73, 0x73, 0x0d, 0xed, 0x60, 0xec,
             0x44, 0x75, 0x0f, 0xe3, 0xb8, 0x3b, 0x15, 0x72])

empty_ct = bytes.fromhex("3e7984d7483781dc6c63d30002ae15b8")
print(f"key   = {RK0.hex()}")
print(f"emptyCT = {empty_ct.hex()}")

pt = aes_decrypt(empty_ct, RK0)
print(f"AES-Decrypt(emptyCT, key) = {pt.hex()}")

# Round-trip test:
ct = aes_encrypt(pt, RK0)
print(f"AES-Encrypt(decrypted, key) = {ct.hex()} (should match emptyCT: {ct == empty_ct})")

# Decrypt the four target blocks from the task:
target_blocks_displayed = [
    # row pair displayed bytes
    "71 80 dd 08 6c 43 37 6b 3c a8 e2 68 6d 0a 97 9b",
    "f8 23 b9 66 6a b9 92 d3 cd ad 80 cf e8 5a ed 1f",
    "c5 c4 6c 60 c0 a3 a5 c9 11 a1 d1 98 f1 83 53 95",
    "53 e4 b9 7c 16 5f c4 3b a3 f5 1e 12 53 1f ea ca",
]

# Display = byte-reversed copy of M_00325 → so M_00325 = byte-reverse of the displayed block.
print("\nDecrypted plaintext per slot:")
for i, blk in enumerate(target_blocks_displayed):
    disp = bytes.fromhex(blk.replace(" ", ""))
    m325 = bytes(reversed(disp))  # byte-reverse
    pt = aes_decrypt(m325, RK0)
    print(f"  slot {i}: ct(M_00325)={m325.hex()}  pt={pt.hex()}  ascii={pt!r}")
