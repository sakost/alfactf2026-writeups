# Dresscode — alfaCTF 2026

**Category:** Crypto / Web  
**Difficulty:** Hard  
**Tags:** crypto, web, sqli, aes-cbc, mac-malleability, iv-flip, race  
**Flag:** `alfa{5mO7rYA_KAK01_fAbR1C_SMotryA_sK0lKO_D3TAIl5}`

## Overview

An online outdoor-clothing shop ("Gorpcore"). Users register, get 100 credits, and must collect items from all 8 categories (jacket, pants, shorts, tshirt, sneakers, cap, gloves, accessories) to pass the "dress code" check and receive the flag. The cheapest possible outfit costs 703 credits — far more than the starting balance of 100. There is no top-up mechanism.

## Architecture

| Service | Role |
|---------|------|
| **shop** (Flask) | Web frontend. Encrypts transactions, writes them to MySQL. |
| **validator** (Rust) | Polls MySQL every 3 s for pending transactions, verifies MAC, decrypts AES-CBC ciphertext, executes the business logic (register / purchase). |
| **MySQL** | Shared state. The `shop_user` DB account has SELECT/INSERT/UPDATE on `transactions`. |

Purchases work asynchronously: the shop encrypts the order data with AES-256-CBC, computes an HMAC-SHA256 tag, and inserts a row into `transactions`. The validator picks it up, checks the MAC, decrypts, and processes.

## Vulnerability

### 1. MAC does not cover the IV (crypto)

```python
# shop/app.py:121-129
cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
mac = hmac.new(MAC_KEY, ciphertext, hashlib.sha256).hexdigest()
```

The HMAC is computed over the **ciphertext only**. The IV is stored separately and is **not** authenticated. In CBC mode, flipping a bit in the IV flips the same bit in the **first 16 bytes of plaintext** without affecting subsequent blocks or the MAC.

### 2. SQL injection in `update_comment` (web)

```python
# shop/app.py:533
query = f"UPDATE transactions SET comment = '{new_comment}' WHERE id = '{order_id}'"
```

The `comment` parameter from a POST form is interpolated directly into an UPDATE query. This lets us modify **any column** of the transaction row — including `iv`.

### 3. Owner bypass in the validator (logic)

```rust
// validator/src/main.rs:283
if data.from == String::from("1000001") {
    // skip balance deduction
}
```

The owner account (`AlexCab`, id `1000001`) has a balance of 999 999 999 and is exempt from balance deduction. If `data.from` equals `1000001` after decryption, any purchase amount passes the balance check and no money is subtracted.

## Exploit — CBC IV-flip via SQLi

A purchase transaction's plaintext (produced by `json.dumps`) looks like:

```
{"from": "DDDDDDD", "to": "DDDDDDD", "items": [...], "amount": ...}
```

The first 16 bytes are `{"from": "DDDDDD` (bytes 0–15), where `D` are the first six digits of our 7-digit user ID. Byte 16 is the 7th digit — it is **not** affected by an IV change.

**Goal:** flip bytes 10–15 of the plaintext from our six leading digits to `100000`, so that `from` reads `"1000001"` (the owner). This requires the 7th digit of our user ID to already be `1`.

### Steps

1. **Register accounts** until we get a `user_id` ending in `1` (~10 % chance per attempt).
2. **Add one item per category** to the cart (8 items, total 703 credits).
3. **POST `/checkout`** — creates a pending, unprocessed transaction. Extract `order_id` from the redirect.
4. **Immediately POST `/orders/<order_id>/update_comment`** with an SQLi payload that XORs the IV in-place inside MySQL:

   ```sql
   x', iv = CONCAT(
     SUBSTR(iv,1,20),
     LPAD(HEX(CONV(SUBSTR(iv,21,2),16,10) ^ d10),2,'0'),
     LPAD(HEX(CONV(SUBSTR(iv,23,2),16,10) ^ d11),2,'0'),
     LPAD(HEX(CONV(SUBSTR(iv,25,2),16,10) ^ d12),2,'0'),
     LPAD(HEX(CONV(SUBSTR(iv,27,2),16,10) ^ d13),2,'0'),
     LPAD(HEX(CONV(SUBSTR(iv,29,2),16,10) ^ d14),2,'0'),
     LPAD(HEX(CONV(SUBSTR(iv,31,2),16,10) ^ d15),2,'0')
   ) WHERE id = '<order_id>' -- 
   ```

   where `d10…d15 = ord(uid[i]) ^ ord(target[i])` for the six differing positions. The XOR is computed inside MySQL — we never need to read the original IV.

5. The **validator** picks up the modified transaction within ~3 s:
   - MAC check passes (ciphertext unchanged).
   - Decryption with the new IV yields `"from": "1000001"`.
   - Balance check passes (owner has 999 M credits).
   - Balance deduction skipped (owner special case).
   - Items inserted into **our** inventory (`"to"` is beyond byte 15, unchanged).
6. **GET `/check_dresscode`** — all 8 categories present, flag awarded.

### Race condition

The validator polls every 3 s. We must fire the SQLi **before** it picks up the transaction. Since `/checkout` returns immediately (no blocking wait) and network round-trip is ~100–250 ms, the window is comfortable.

## Flag

`alfa{5mO7rYA_KAK01_fAbR1C_SMotryA_sK0lKO_D3TAIl5}`

## Key Takeaways

- "Encrypt-then-MAC" only protects what the MAC covers. CBC plaintexts whose IV is stored separately are malleable in their first 16 bytes regardless of how strong the MAC is — `HMAC(ciphertext)` is *not* `HMAC(IV ‖ ciphertext)`.
- An SQLi that doesn't reach `users` or `flags` is not "low-impact". When the queue table contains crypto material (IVs, nonces, salts), even a per-row UPDATE primitive becomes a tampering primitive on every row in flight.
- Owner / superuser fast-paths inside async workers are dangerous when the worker authenticates the request only by a decrypted field. The check needs to be on the *signed* envelope, not the *decrypted* payload.
