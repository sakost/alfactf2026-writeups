#!/usr/bin/env python3
import requests

P = 72057594037927931

def sig_of(data: bytes) -> int:
    s = 0
    for c in data:
        s = (s * 256 + c) % P
    return s

original_str = "# Подтвержденный аттестат\nпаспорт: \"1337676769\"\nоценки:\n  физика: 4\n  химия: 3\n  информатика: 5\n  английский: 4\n  русский: 5\n  литература: 4\n  физкультура: 5\n  обществознание: 3\n  алгебра: 4\n  история: 5\n  география: 4\n  биология: 3\n  геометрия: 4\n"

original_bytes = original_str.encode('utf-8')
target = sig_of(original_bytes)
print(f"Original len: {len(original_bytes)}")
print(f"Target: {target}")

modified_str = "# Подтвержденный аттестат\nпаспорт: \"1337676769\"\nоценки:\n  физика: 5\n  химия: 5\n  информатика: 5\n  английский: 5\n  русский: 5\n  литература: 5\n  физкультура: 5\n  обществознание: 5\n  алгебра: 5\n  история: 5\n  география: 5\n  биология: 5\n  геометрия: 5\n"

# Strategy: same length, modify comment characters to compensate
# The original and modified differ only in grade digits
# Let's compute the positions of changed bytes

orig_bytes = original_str.encode('utf-8')
mod_bytes = modified_str.encode('utf-8')

assert len(orig_bytes) == len(mod_bytes), f"Length mismatch: {len(orig_bytes)} vs {len(mod_bytes)}"

n = len(orig_bytes)
print(f"String length: {n} bytes")

# Find differing positions
diffs = []
for i in range(n):
    if orig_bytes[i] != mod_bytes[i]:
        diffs.append((i, orig_bytes[i], mod_bytes[i]))
        print(f"  pos {i}: {orig_bytes[i]} ({chr(orig_bytes[i])}) -> {mod_bytes[i]} ({chr(mod_bytes[i])})")

# Compute hash delta from grade changes
delta = 0
for pos, old, new in diffs:
    delta = (delta + (new - old) * pow(256, n - 1 - pos, P)) % P

print(f"Delta from grade changes: {delta}")
print(f"Need to subtract delta: {(-delta) % P}")

# I need to find changes in the comment that compensate for delta.
# The comment is "# Подтвержденный аттестат" at the start.
# Comment bytes start at position 2 (after "# ")
# "Подтвержденный аттестат" in UTF-8

comment_text = "Подтвержденный аттестат"
comment_bytes = comment_text.encode('utf-8')
print(f"Comment: {comment_text} ({len(comment_bytes)} bytes)")
print(f"Comment starts at position 2 in the string")

# I can change characters in the comment. Each Cyrillic char is 2 bytes.
# Let me try changing the last character of the comment to compensate.
# If I change byte at position p from val a to val b:
#   contribution = (b - a) * 256^(n-1-p) mod P
# I need the total of my compensating changes = (-delta) mod P

neg_delta = (-delta) % P

# Try changing ONE byte in the comment. Position p, from orig_bytes[p] to some value v.
# Need: (v - orig_bytes[p]) * 256^(n-1-p) ≡ neg_delta (mod P)
# v - orig_bytes[p] ≡ neg_delta * inv(256^(n-1-p)) (mod P)
# v = orig_bytes[p] + neg_delta * inv(256^(n-1-p)) mod P

# Since P is prime, we can compute modular inverse
for p in range(2, 2 + len(comment_bytes)):
    power = pow(256, n - 1 - p, P)
    inv_power = pow(power, P - 2, P)
    diff_needed = (neg_delta * inv_power) % P
    v = (mod_bytes[p] + diff_needed) % P  # using mod_bytes since that's what we're starting from
    if 0 <= v <= 255:
        print(f"  Single byte change at pos {p}: {mod_bytes[p]} -> {v}")
        # Check if it's valid UTF-8 when combined with adjacent bytes
        break

# That won't work since v will be huge (mod P).
# Let me try changing TWO adjacent bytes to form a valid Cyrillic character.

# For a 2-byte Cyrillic UTF-8 char: first byte in 0xC0-0xDF, second in 0x80-0xBF
# Most Cyrillic: first byte 0xD0 or 0xD1, second 0x80-0xBF

# Let me try all Cyrillic character positions in the comment
# Comment characters start at byte offset 2
# Each Cyrillic char is 2 bytes

comment_start = 2
char_positions = []  # (byte_offset, char)
i = 0
byte_offset = comment_start
while i < len(comment_bytes):
    if comment_bytes[i] >= 0xC0:
        char_len = 2
    else:
        char_len = 1
    char_positions.append((byte_offset, comment_bytes[i:i+char_len]))
    i += char_len
    byte_offset += char_len

print(f"\nComment characters:")
for pos, cb in char_positions:
    print(f"  byte {pos}: {cb.hex()} = {cb.decode('utf-8')}")

# Try changing 2 bytes at each character position
# For positions p and p+1, changing from (a0, a1) to (b0, b1):
# (b0-a0)*256^(n-1-p) + (b1-a1)*256^(n-2-p) ≡ neg_delta (mod P)
# Let's fix b0 and solve for b1, trying all valid b0 values

print(f"\nSearching for valid Cyrillic character substitutions...")
found = False

# Try each character position
for char_idx, (pos, orig_char_bytes) in enumerate(char_positions):
    if len(orig_char_bytes) != 2:
        continue
    a0, a1 = mod_bytes[pos], mod_bytes[pos + 1]
    p0_power = pow(256, n - 1 - pos, P)
    p1_power = pow(256, n - 2 - pos, P)

    # Try all valid first bytes for Cyrillic (0xD0, 0xD1)
    for b0 in [0xD0, 0xD1]:
        # (b0-a0)*p0_power + (b1-a1)*p1_power ≡ neg_delta (mod P)
        # (b1-a1) ≡ (neg_delta - (b0-a0)*p0_power) * inv(p1_power) (mod P)
        remaining = (neg_delta - (b0 - a0) * p0_power) % P
        inv_p1 = pow(p1_power, P - 2, P)
        diff_b1 = (remaining * inv_p1) % P
        b1 = (a1 + diff_b1) % P

        if 0x80 <= b1 <= 0xBF:
            # Valid continuation byte!
            new_char = bytes([b0, b1])
            try:
                decoded = new_char.decode('utf-8')
                print(f"Found! Change char at pos {pos}: {orig_char_bytes.hex()} ({orig_char_bytes.decode('utf-8')}) -> {new_char.hex()} ({decoded})")

                # Build the crafted attestat
                crafted = bytearray(mod_bytes)
                crafted[pos] = b0
                crafted[pos + 1] = b1
                crafted = bytes(crafted)

                crafted_sig = sig_of(crafted)
                print(f"Crafted sig: 0x{crafted_sig:016x}, target: 0x{target:016x}, match: {crafted_sig == target}")

                if crafted_sig == target:
                    # Verify YAML still parses
                    import yaml
                    parsed = yaml.safe_load(crafted.decode('utf-8'))
                    print(f"YAML parse: {parsed}")

                    # Submit
                    print("\n--- Submitting ---")
                    url = "https://gradebook-4cgg0nsz.alfactf.ru/submit"
                    resp = requests.post(url, data={"attestat": crafted.decode('utf-8')})
                    print(resp.text)
                    found = True
                    break
            except:
                pass
    if found:
        break

if not found:
    # Try changing two character positions
    print("\nTrying two character changes...")
    # Fix one change to a known valid char, then solve for the second
    for i, (pos_i, orig_i) in enumerate(char_positions):
        if len(orig_i) != 2:
            continue
        a0_i, a1_i = mod_bytes[pos_i], mod_bytes[pos_i + 1]
        p0_i = pow(256, n - 1 - pos_i, P)
        p1_i = pow(256, n - 2 - pos_i, P)

        # Try changing this char to various Cyrillic chars
        for b0_i in [0xD0, 0xD1]:
            for b1_i in range(0x80, 0xC0):
                if b0_i == a0_i and b1_i == a1_i:
                    continue
                try:
                    bytes([b0_i, b1_i]).decode('utf-8')
                except:
                    continue

                # Contribution of this change
                contrib_i = ((b0_i - a0_i) * p0_i + (b1_i - a1_i) * p1_i) % P
                remaining = (neg_delta - contrib_i) % P

                # Now find a second character change
                for j, (pos_j, orig_j) in enumerate(char_positions):
                    if j == i or len(orig_j) != 2:
                        continue
                    a0_j, a1_j = mod_bytes[pos_j], mod_bytes[pos_j + 1]
                    p0_j = pow(256, n - 1 - pos_j, P)
                    p1_j = pow(256, n - 2 - pos_j, P)

                    for b0_j in [0xD0, 0xD1]:
                        inv_p1_j = pow(p1_j, P - 2, P)
                        diff_needed = (remaining - (b0_j - a0_j) * p0_j) % P
                        diff_b1 = (diff_needed * inv_p1_j) % P
                        b1_j = (a1_j + diff_b1) % P

                        if 0x80 <= b1_j <= 0xBF:
                            new_j = bytes([b0_j, b1_j])
                            try:
                                decoded_j = new_j.decode('utf-8')
                                new_i = bytes([b0_i, b1_i])
                                decoded_i = new_i.decode('utf-8')

                                crafted = bytearray(mod_bytes)
                                crafted[pos_i] = b0_i
                                crafted[pos_i + 1] = b1_i
                                crafted[pos_j] = b0_j
                                crafted[pos_j + 1] = b1_j
                                crafted = bytes(crafted)

                                crafted_sig = sig_of(crafted)
                                if crafted_sig == target:
                                    print(f"Found with 2 changes!")
                                    print(f"  pos {pos_i}: -> {decoded_i}")
                                    print(f"  pos {pos_j}: -> {decoded_j}")
                                    print(f"Crafted text:\n{crafted.decode('utf-8')}")

                                    url = "https://gradebook-4cgg0nsz.alfactf.ru/submit"
                                    resp = requests.post(url, data={"attestat": crafted.decode('utf-8')})
                                    print(resp.text)
                                    found = True
                                    break
                            except:
                                pass
                    if found:
                        break
                if found:
                    break
        if found:
            break

    if not found:
        print("No solution found")
