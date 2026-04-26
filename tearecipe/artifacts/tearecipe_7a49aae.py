#!/usr/bin/env python3
# brewing: ht409 (Hina Takahashi), encryption: yo660 (Yuto Ogawa), vibecoding: cp500 (Chihiro Punaki), original tea recipe: gs001 (Genryu Saito)

import sys

d1, d2, reg, taps, n = b'\x18Pf\xc7\xee\x0f-.\x8fBv 0\x9b\xb8\xf1\xb1\xb6G\x86Q\x9aFj\xdb\xee\x08 c\x89\rr#e\x8e\xfd\xf5\xf8\xe4\\\xd3U\xd5Rn\xc7\xaf\tl!\x98\x07hsd\x9f\xf9\xa7\xef\xec', b'\x02Tc\xca\xe7\x10)c\x8e\x07~!0\x9d\xed\xe2\xa7\xb0\x1e\x9d\x08\xd5en\xc2\xed]-c\x99\x0bo', 170, 0x88, 8

if len(sys.argv) <= 1:
    data = d1  # FAIL
elif bytes([n + 1 for n in sys.argv[1].encode()]).upper() != b'IJSBLFHPNB':
    data = d1  # FAIL
else:
    data = d2  # SUCCESS
ks = bytearray(len(data))
for i in range(len(data)):
    for j in range(8): ks[i] |= (reg & 1) << (7 - j); reg = (reg >> 1) | (((reg & taps).bit_count() & 1) << (n - 1))
enc = bytes(a ^ b for a, b in zip(data, ks))
print(enc.decode())
#print(f"{bytes(a ^ b for a, b in zip(enc, ks))}")
#\x18Pf\xc7\xee\x0f-.\x8fBv 0\x9b\xb8\xf1\xb1\xb6G\x86Q\x9aFj\xdb\xee\x08 c\x89\rr#e\x8e\xfd\xf5\xf8\xe4\\\xd3U\xd5Rn\xc7\xaf\tl!\x98\x07hsd\x9f\xf9\xa7\xef\xec%‰”—–™£@¢¨¢%‰†@“…•M¢¨¢K™‡¥]~~ò@•„@¢¨¢K™‡¥JñZ@~~@ˆ‰”…£ˆ‰”‰£¢¤z%@@@@„£k@™…‡k@£—¢k@•@~@‚à§ðƒ_©à§øùà§…ùà§ð†]ƒà§ø‚Âˆzƒà§ù†à§‚øà§…à§‚õà§à§ñðà§øöÉà§øñÅà§÷†à§„à§‚òÙƒ÷à§øõà£†Lƒà§ù‚à§††à§…òà§†ùà§‚„Òà§ù†Ãà§ùôç“à§„†à§…öâ`aà§øƒà§ðó»}¥à§„ôà§…à§†òà§†‚k@ñ÷ðk@ð§øøk@ø^@’¢@~@‚¨£…™™¨M“…•M„£]]%…“¢…z%@@@@„£k@™…‡k@£—¢k@•@~@‚}à§ñø×†à§ƒ÷à§……à§ð†`Kà§ø†Â¥@ðà§ù‚à§‚øà§†ñà§‚ñà§‚öÇà§øöØà§ùÆ‘à§„‚à§……à§ðø@ƒà§øùà™™{…à§ø…à§†„à§†õà§†øà§…ôààà§„óäà§„õÙ•à§ƒ÷à§†à£“Oà§ùøà§ð÷ˆ¢„à§ù†à§†ùà§÷à§…†à§…ƒ}k@ñ÷ðk@ð§øøk@ø^@’¢@~@‚¨£…™™¨M“…•M„£]]%†–™@‰@‰•@™•‡…M“…•M„£]]z%@@@@†–™@‘@‰•@™•‡…Mø]z@’¢J‰Z@»~@M™…‡@P@ñ]@LL@M÷@`@‘]^@™…‡@~@M™…‡@nn@ñ]@»@MMM™…‡@P@£—¢]K‚‰£mƒ–¤•£M]@P@ñ]@LL@M•@`@ñ]]%…•ƒ@~@‚¨£…¢M@_@‚@†–™@k@‚@‰•@©‰—M„£k@’¢]]%—™‰•£M…•ƒK„…ƒ–„…M]]%{
