import sys
import os
import binascii
from typing import Optional

from Crypto.Hash import SHA256


def sha256sum_file(filename: str, chunk_sz=512) -> Optional[bytes]:
    # Checks + open file
    if not os.path.exists(filename):
        return None
    # sha256 ctx init
    sha256_ctx = SHA256.new()
    # read file + update sha256 ctx
    with open(filename, 'rb') as f_in:
        data = f_in.read(chunk_sz)
        while len(data) > 0:
            sha256_ctx.update(data)
            data = f_in.read(chunk_sz)
    return sha256_ctx.digest()

    

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <filename>')
        sys.exit(1)
    # else:
    digest = sha256sum_file(sys.argv[1])
    if digest is not None:
        print(f'{binascii.hexlify(digest).decode()}')
    else:
        print(f'error')
    sys.exit(0)
