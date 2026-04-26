# Red Flag — alfaCTF 2026

**Category:** Misc / Linux  
**Difficulty:** Easy  
**Tags:** linux, logic, shell, tui, mv-trick  
**Flag:** `alfactf{mv_from_W3B_ui_T0_wHIpT4il}`

## Overview

We're given SSH access to a server running a bash-based tier list service (`redflag.sh`). The app uses `whiptail` for a TUI menu. Users can create tier lists, add tiers/items, join others' tier lists, and browse public ones. Some items are marked `[LOCKED]` via a `restricted=` field in each tier list's `.meta` file — only the owner can view them.

The goal: read the locked item inside a tier list owned by `nastya_gorp`, a reserved user we cannot log in as.

## Vulnerability

The `join_tierlist_by_name` function renames the tier list directory by appending `__with__<username>`:

```bash
mv "$TIERLISTS_DIR/$tl_name" "$TIERLISTS_DIR/${tl_name}__with__${CURRENT_USER}"
```

There is **no check** whether the destination directory already exists. On Linux, `mv src dst` where `dst` is an existing directory moves `src` **inside** `dst` (i.e. `dst/src`), rather than failing or overwriting.

Two more factors complete the exploit:

1. `view_tierlist` uses **recursive** `find` with no `-maxdepth`:
   ```bash
   find "$tl_dir" -type d -name 'tier_*' -print0
   ```
   This discovers tier directories at any nesting depth — including a tier list moved inside ours.
2. `is_restricted` reads the `.meta` of the **outer** directory (`$tl_dir`), not the nested original. Since our `.meta` has `restricted=` empty, locked items from the nested tier list show as unrestricted.

## Exploit

1. SSH in: `ssh redflag@redflag-h306xs1x.alfactf.ru`.
2. Log in as `pwn` (any valid non-reserved username).
3. Browse **public tier lists** to discover the target name: `layering_tierlist` (owned by `@nastya_gorp`).
4. **Create** a tier list named `layering_tierlist__with__pwn` — pre-creates the destination directory.
5. Go back to public tier lists, select `layering_tierlist`, click **"Join"**.
6. The script runs `mv .../layering_tierlist .../layering_tierlist__with__pwn`. Since the destination exists, `layering_tierlist` is moved **inside** it.
7. The view now shows `layering_tierlist__with__pwn` with us as owner. Recursive `find` picks up `layering_tierlist__with__pwn/layering_tierlist/tier_*/` and lists all items — including the previously locked one — using **our** `.meta` (no restrictions).
8. Click the item to read the flag.

## Flag

`alfactf{mv_from_W3B_ui_T0_wHIpT4il}`

## Note
> AI chose wrong user to exploit - should've been admin.
