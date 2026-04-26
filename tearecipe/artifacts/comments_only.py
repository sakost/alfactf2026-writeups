
# import sys
# if len(sys.argv)==2 and sys.argv[1] == "himetahimitsu":
#     data, reg, taps, n = b"\x0c^z\x89\xe9\x0f)c\x8bBh:c\x9f\xb8\xea\xb5\xaa\x10\x86I\x81E\x7f\xda\xb2Rc7\x85\tf<c\x9b\xff\xe2\xf9\xbdK\x9fC\x94Xl\xdf\xe6S-/\x8c\x03|'v\xd4\xea\xf2\xfb", 170, 0x88, 8; ks = bytearray(len(data))
# else:
#     data, reg, taps, n = b'\x18Pf\xc7\xee\x0f-.\x8fBv 0\x9b\xb8\xf1\xb1\xb6G\x86Q\x9aFj\xdb\xee\x08 c\x89\rr#e\x8e\xfd\xf5\xf8\xe4\\\xd3U\xd5Rn\xc7\xaf\tl!\x98\x07hsd\x9f\xf9\xa7\xef\xec', 170, 0x88, 8; ks = bytearray(len(data))
# for i in range(len(data)):
#     for j in range(8): ks[i] |= (reg & 1) << (7 - j); reg = (reg >> 1) | (((reg & taps).bit_count() & 1) << (n - 1))
# enc = bytes(a ^ b for a, b in zip(data, ks))
# print(enc.decode())
#
