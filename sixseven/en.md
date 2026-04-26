# Six Seven — alfaCTF 2026

**Category:** Crypto / Math / Web  
**Difficulty:** Medium  
**Tags:** crypto, shamir-secret-sharing, polynomial, crt, factorization, web  
**Flag:** `alfa{esPress0_MaccHiAt0_pOR_F4VOr3}`

## Overview

The challenge is a coffee-shop loyalty program "У Шамира" (At Shamir's) implementing Shamir's Secret Sharing. Buy 6 espressos to collect 6 polynomial shares (threshold 6, degree 5), reconstruct the secret (`coupon_secret`), submit it as a coupon, and receive the flag via a QR code.

The catch: you start with **40 coins** and each espresso costs **10 coins** — only enough for **4 espressos**, 2 short of the threshold.

## Recon

The project directory contains both source code and a git repo with three commits:

```
a28c686  Fix: blur flag
c67f4b0  Second commit: change to pure python
ab6813d  First commit
```

The first commit includes a **Rust API service** (`api/src/main.rs`, 835 lines) that was removed in the second commit. However, the **nginx config still proxies `/api/`** to a separate backend — and the API service is live in production.

```
# nginx/default.conf
location /api/ {
    set $sixseven_api http://api:5000;
    proxy_pass $sixseven_api;
}
```

## Architecture

- **Flask app** (`app/app.py`, `app/service.py`): registration, login, espresso purchases, coupon validation, flag delivery.
- **Rust API** (`api/src/main.rs`): polynomial/share operations. Shares a SQLite DB with the Flask app.
- **Per-user crypto state** (in `users` table):
  - `module_q` — 256-bit prime (the finite-field modulus)
  - `poly_coeffs` — JSON array of 6 integer coefficients `[a_0, a_1, ..., a_5]`
  - `coupon_secret` — the polynomial's constant term `a_0 = f(0)`

Each espresso purchase generates a random UUID `order_id`, computes `share = f(uuid_to_int(order_id)) mod module_q`, and stores both. The x-coordinate of each share is the UUID interpreted as a 128-bit integer.

## Vulnerabilities

### 1. Hidden API with `set_module` endpoint

The Rust API exposes:

| Endpoint              | Method | Purpose                                    |
|-----------------------|--------|--------------------------------------------|
| `/api/get_module`     | GET    | Read user's `module_q`                     |
| `/api/set_module`     | POST   | **Write** user's `module_q`                |
| `/api/calc_shares`    | GET    | Re-evaluate polynomial at all order UUIDs  |
| `/api/combine_shares` | POST   | Lagrange interpolation over provided shares|
| `/api/check_coupon`   | POST   | Boolean oracle: does coupon match secret?  |

`set_module` allows overwriting `module_q` to any value `q ∈ [2^63, 2^300)` that passes a Fermat primality test with bases `{2, 3, 5, 7, 11, 13, 17}`. The polynomial coefficients and `coupon_secret` in the DB are **not** modified.

### 2. Polynomial re-evaluation leaks the secret

`calc_shares` re-evaluates the stored polynomial using the **current** `module_q`:

```rust
let share_value = evaluate_polynomial(&coeffs, &x_value, &module_q);
```

If we set `module_q = q` where `q` divides some order UUID `x_i`, then `x_i ≡ 0 (mod q)`, so:

```
f(x_i) mod q = a_0 + a_1·0 + a_2·0² + ... = a_0 mod q = coupon_secret mod q
```

This leaks `coupon_secret mod q` from a **single share**, bypassing the threshold entirely.

### 3. Compressed-cookie rejection in Rust auth

The Rust API verifies Flask session cookies via HMAC-SHA1, but rejects cookies whose signed payload starts with `.` (Flask's marker for zlib-compressed payloads). Flash messages inflate the session and trigger compression. Consuming flashes by visiting `/dashboard` after login yields a small uncompressed cookie the API accepts.

## Exploit

### Step 1 — Find a lucky account

Register accounts and buy 4 espressos each. For each account, factor the 4 order UUIDs (128-bit integers). We need the **sum of bit-lengths of prime factors ≥ 2^63** across all UUIDs to exceed 256 (the secret size).

A typical 128-bit random number has its largest prime factor around 80 bits (Dickman's function), so ~3 attempts suffice.

### Step 2 — Recover `coupon_secret` via CRT

For each UUID with a usable prime factor `q ≥ 2^63`:

1. `POST /api/set_module` — set `module_q = q`.
2. `GET /api/calc_shares` — read the share for that UUID → `coupon_secret mod q`.

Repeat for all usable primes, then apply the **Chinese Remainder Theorem** to recover `coupon_secret` modulo the product of all primes. Since the product exceeds `2^256` and `coupon_secret < 2^256`, we recover it exactly.

### Step 3 — Claim the flag

1. `POST /api/check_coupon` — sanity-check the recovered secret (optional).
2. `POST /buy-exclusive` with `coupon=<secret>` — creates an exclusive order.
3. `GET /orders/<exclusive_id>/qr.svg` — decode the QR for the flag.

```python
# Factor UUID, find prime divisor >= 2^63 that passes Fermat
def find_usable_q(uuid_int):
    factors = factorint(uuid_int)
    for p in factors:
        if p >= (1 << 63) and passes_fermat(p):
            return p
    return None

# For each usable UUID: set q, get shares, extract a_0 mod q
for order_id in order_ids:
    x = uuid.UUID(order_id).int
    q = find_usable_q(x)
    if q is None:
        continue
    client.post(f'/api/set_module?user_id={uid}', json={'q': str(q)})
    shares = client.get(f'/api/calc_shares?user_id={uid}').json()['shares']
    for s in shares:
        if s['id'] == order_id:
            residues.append((q, int(s['share'])))

# CRT to recover full secret
secret = crt([r[0] for r in residues], [r[1] for r in residues])

# Submit and get flag
client.post('/buy-exclusive', data={'coupon': str(secret)})
```

## Flag

`alfa{esPress0_MaccHiAt0_pOR_F4VOr3}`

## Key Takeaways

- A removed-but-still-deployed service is a recurring real-world bug: the second commit in git is **not** the production state when nginx still proxies to the deleted backend. Always look at the runtime topology, not just `HEAD`.
- A Shamir scheme is only as strong as the integrity of its public parameters. Letting the *user* overwrite the modulus while leaving the polynomial fixed lets a single share reveal `f(0) mod q` whenever `q` divides any x-coordinate — defeating the threshold property entirely.
- Random 128-bit UUIDs are factorisable cheaply (largest prime factor ≈ 80 bits on average), and CRT composes residues across the usable primes to exactly recover any 256-bit secret in a few attempts. UUIDs are not opaque numbers — they have arithmetic structure.
