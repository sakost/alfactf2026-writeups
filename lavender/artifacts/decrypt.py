#!/usr/bin/env python3
"""
Decrypt an HFL1 envelope (RSA-OAEP-SHA256 wrap + AES-256-GCM body).

Format:
  magic[4]      = "HFL1"
  version[1]
  keyAlgo[1]    = 1 (RSAOAEP)
  dataAlgo[1]   = 1 (AESGCM)
  wrappedKeyLen[2]  BE uint16
  nonceLen[2]       BE uint16
  ciphertextLen[4]  BE uint32
  wrappedKey[wrappedKeyLen]
  nonce[nonceLen]
  ciphertext+tag[ciphertextLen]
"""
import struct
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main(envelope_path, key_path):
    with open(envelope_path, "rb") as f:
        blob = f.read()

    assert blob[:4] == b"HFL1", f"bad magic: {blob[:4]!r}"
    off = 4
    version = blob[off]; off += 1
    key_algo = blob[off]; off += 1
    data_algo = blob[off]; off += 1
    wrapped_len = struct.unpack(">H", blob[off:off+2])[0]; off += 2
    nonce_len = struct.unpack(">H", blob[off:off+2])[0]; off += 2
    ct_len = struct.unpack(">I", blob[off:off+4])[0]; off += 4
    print(f"version={version} keyAlgo={key_algo} dataAlgo={data_algo} "
          f"wrapped={wrapped_len} nonce={nonce_len} ct={ct_len}")

    wrapped = blob[off:off+wrapped_len]; off += wrapped_len
    nonce = blob[off:off+nonce_len]; off += nonce_len
    ct = blob[off:off+ct_len]; off += ct_len
    assert off == len(blob), f"trailing bytes: {len(blob)-off}"

    with open(key_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)

    aes_key = priv.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print(f"unwrapped AES key (len={len(aes_key)}): {aes_key.hex()}")

    plain = AESGCM(aes_key).decrypt(nonce, ct, None)
    sys.stdout.buffer.write(plain)
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
