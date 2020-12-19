import sys
import binascii
import string
from typing import Optional
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from struct import pack


def deriv_password(password,salt,counter):
    if len(salt) < 8:
        print("Salt Error")
        return None
    
    #Compute H0
    sha256_ctx = SHA256.new()
    sha256_ctx.update(password.encode())
    sha256_ctx.update(salt)
    sha256_ctx.update(pack('<I',0))
    H0 = sha256_ctx.digest()

    #Compute Hi
    Hi = H0
    for i in range(1,counter):
        sha256_ctx = SHA256.new()
        sha256_ctx.update(Hi)
        sha256_ctx.update(password.encode())
        sha256_ctx.update(salt)
        sha256_ctx.update(pack('<I',0))
        Hi = sha256_ctx.digest()
    return Hi


def deriv_master_key(masterKey):

    sha256_ctx = SHA256.new()
    sha256_ctx.update(masterKey)
    sha256_ctx.update(pack('<B',0))
    cipher_key = sha256_ctx.digest()

    sha256_ctx = SHA256.new()
    sha256_ctx.update(masterKey)
    sha256_ctx.update(pack('<B',1))
    integrity_key = sha256_ctx.digest()

    return cipher_key, integrity_key


if __name__ == '__main__':
    if len(sys.argv) !=2:
        print("[ERROR] usage is : {sys.argv[0]} <password>")
        sys.exit(1)
    
    salt = get_random_bytes(8)
    salt = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    master_Key = deriv_password(sys.argv[1],salt,0)
    print("Salt: "+binascii.hexlify(salt).decode())
    print("Master Key: "+binascii.hexlify(master_Key).decode())


    cipher_key,integrity_key = deriv_master_key(master_Key)
    print("cipher_key: "+binascii.hexlify(cipher_key).decode())
    print("integr_key: "+binascii.hexlify(integrity_key).decode())