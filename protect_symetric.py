import sys
import binascii
import string
from typing import Optional
from Crypto.Random import get_random_bytes
from struct import pack
from Crypto.Cipher import AES

def protect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    #AES-CBC-256
    pass


if __name__ == '__main__':
    if len(sys.argv) !=2:
        print("[ERROR] usage is : {sys.argv[0]} <filename>")
        sys.exit(1)
   