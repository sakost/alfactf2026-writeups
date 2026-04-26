# Gradebook — alfaCTF 2026

**Category:** Crypto  
**Difficulty:** Medium  
**Tags:** crypto, rolling-hash, polynomial-hash, forgery, yaml  
**Flag:** `alfactf{attES7A7_V_krOVI_po_B0kAm_koNVoY_A_mEnYa_V35Ut_P0d_S1reni_v0Y}`

## Overview

The service is an admission portal for a fictional university. You submit a YAML "attestat" (transcript) tied to a passport number. The server checks:

1. Valid YAML with the correct structure (13 specific subjects)
2. Passport number exists in the database
3. All grades are in `[1, 5]`
4. **Signature** — a polynomial rolling hash of the raw YAML bytes matches the stored value
5. All grades must be exactly `5` to receive the flag

The original transcript has 3s and 4s, so simply editing them to 5s breaks the signature check.

## The Hash

```go
const sigP uint64 = 72057594037927931 // 2^56 − 5, prime

func sigOf(b []byte) uint64 {
    var s uint64
    for _, c := range b {
        s = (s*256 + uint64(c)) % sigP
    }
    return s
}
```

This is a classic **polynomial rolling hash** (Rabin fingerprint variant): `H = Σ b[i] · 256^(n-1-i) mod P`. It is **not** cryptographic — given the algebraic structure, we can forge collisions.

## Vulnerability

YAML ignores comments (`# ...`). We can append a comment line to the modified (all-5s) transcript without changing how the parser sees it, but the raw bytes (and therefore the hash) change. We control those raw bytes — so we can reach any target hash by tuning the suffix.

## Exploit

After appending `\n# <prefix>` to the modified transcript, we have hash `h`. We need `k` printable ASCII bytes `b[0]..b[k-1]` such that:

```
h · 256^k + b[0]·256^(k-1) + ... + b[k-1] ≡ target  (mod P)
```

Let `R = (target - h · 256^k) mod P`. We need an integer `V = R + j·P` that decomposes into `k` base-256 digits, all in `[32, 126]`.

Since `P = 256^7 - 5`, the upper digits of `V` in base 256 are nearly fixed by `R`. Some `R` values place a fixed digit outside `[32, 126]`, making the equation unsolvable. The fix: try different comment prefixes (`# %%%`, etc.) until the fixed digits land in printable range, then scan `j` for a full solution.

With prefix `%%%` and 10 variable bytes a valid decomposition is found quickly. The crafted YAML:

```yaml
# Подтвержденный аттестат
паспорт: "1337676769"
оценки:
  физика: 5
  химия: 5
  информатика: 5
  английский: 5
  русский: 5
  литература: 5
  физкультура: 5
  обществознание: 5
  алгебра: 5
  история: 5
  география: 5
  биология: 5
  геометрия: 5

# %%% +pX5D~7~}
```

passes all checks and returns the flag.

## Flag

`alfactf{attES7A7_V_krOVI_po_B0kAm_koNVoY_A_mEnYa_V35Ut_P0d_S1reni_v0Y}`

## Files

Solver script: [`artifacts/solve.py`](artifacts/solve.py) — recomputes the polynomial hash, calculates the byte deltas introduced by editing grades to all-5s, and brute-forces a Cyrillic byte substitution in the trailing comment that exactly cancels them.
