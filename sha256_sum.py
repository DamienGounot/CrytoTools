import sys
import os
import binascii
from typing import Optional
from Crypto.Hash import SHA256


def checkSum(filename, chunkSize=512):
    if not os.path.exists(filename):
        return None
    
    sha256_ctx = SHA256.new()
    with open(filename, 'rb') as f_in:
        data = f_in.read(chunkSize)
        while len(data) > 0:
            sha256_ctx.update(data)
            data = f_in.read(chunkSize)
    
    return sha256_ctx.digest()


if __name__ == '__main__':
    if len(sys.argv) !=2:
        print("[ERROR] usage is : {sys.argv[0]} <filename>")
        sys.exit(1)
    
    digest = checkSum(sys.argv[1])
    if digest is not None:
        print(binascii.hexlify(digest).decode())
    else:
        print("Error")
