import sys
import string
import binascii
from struct import pack
from typing import Optional

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def deriv_password(password: str, salt:bytes, counter: int) -> Optional[bytes]:
    """
    Very easy password derivation function
        - H0 = SHA256(password || salt || 0) # 0 == 0x00000000 (little endian, 32bits)
        - Hi = SHA256(Hi-1 || password || salt || i) # i is in little endian, 32bits
    return the value Hn[0:32] ~= H_{counter-1}
    """
    # 01. Compute H0
    sha256_ctx = SHA256.new()
    sha256_ctx.update(password.encode())
    sha256_ctx.update(salt)
    sha256_ctx.update(pack('<I', 0))
    h0 = sha256_ctx.digest()

    # 02. Compute Hi
    hi = h0
    for i in range(1, counter):
        sha256_ctx = SHA256.new()
        sha256_ctx.update(hi)
        sha256_ctx.update(password.encode())
        sha256_ctx.update(salt)
        sha256_ctx.update(pack('<I', i))
        hi = sha256_ctx.digest()
    
    # 03. return Hn
    return hi
# end deriv_password


def deriv_master_key(km: bytes) -> bytes:
    """
    kc = SHA256(km || 0x00) [0:32] -> only the 256 first bits
    ki = SHA256(km || 0x01) [0:32] -> only the 256 first bits
    """
    #kc = SHA256.new(km + pack("<B", 0)).digest()
    #ki = SHA256.new(km + pack("<B", 1)).digest()
    sha256_ctx = SHA256.new()
    sha256_ctx.update(km)
    sha256_ctx.update(pack("<B", 0))
    kc = sha256_ctx.digest()
    
    sha256_ctx = SHA256.new()
    sha256_ctx.update(km)
    sha256_ctx.update(pack("<B", 1))
    ki = sha256_ctx.digest()

    return kc, ki



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <password>')
        sys.exit(1)
    # else:
    COUNTER = 1024
    # 01. salt generation (64bits)
    salt = get_random_bytes(8)
    salt = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    # 02. password derivation
    km = deriv_password(sys.argv[1], salt, COUNTER)
    # 03. print K, salt
    print(f'salt = {binascii.hexlify(salt).decode()}')
    print(f'Km   = {binascii.hexlify(km).decode()}')
    # 04. deriv KM
    kc, ki = deriv_master_key(km)
    print(f'kc   = {binascii.hexlify(kc).decode()}')
    print(f'ki   = {binascii.hexlify(ki).decode()}')
    
    sys.exit(0)

# Km   = da6c160d54fc511ebff51cebeab86d8177df2e5746305a4a69b9b6db9e9b5fb2
# salt = 0000000000000000
