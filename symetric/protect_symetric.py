import sys
import os
import string
import binascii
from struct import pack
from typing import Optional
 
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad
 
 
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
 
 
def compute_hmac_sha256(key: bytes, *buffers) -> bytes:
    _hmac = HMAC.new(key, digestmod=SHA256.new())
    for b in buffers:
        _hmac.update(b)
    return _hmac.digest()
# end compute_hmac_sha256
 
 
def verify_hmac_sha256(key: bytes, hmac_value: bytes, *buffers):
    _hmac = compute_hmac_sha256(key, *buffers)
    return _hmac == hmac_value
# end verify_hmac_sha256
 
 
def protect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    padded_input = pad(buffer, AES.block_size)
    return aes.encrypt(padded_input)
 
 
def unprotect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(buffer)
    return unpad(decrypted_data, AES.block_size)
 
 
def main(argv):
    # 00. check arguments
    if len(argv) != 4:
        print("usage: {0} <password> <input_file> <output_file>".format(argv[0]))
        sys.exit(1)
    _password = argv[1]
    _input_file_path = argv[2]
    _output_file_path = argv[3]
 
 
    # 01. read input file
    _plain_data = b''
    if os.path.exists(_input_file_path):
        _sz = os.path.getsize(_input_file_path)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        with open(_input_file_path, "rb") as f_in:
            _plain_data = f_in.read()
 
 
    # 02. derive password -> km
    _salt = get_random_bytes(8)
    _km = deriv_password(_password, _salt, 6000)
 
 
    # 03. derive km -> kc & ki
    _kc, _ki = deriv_master_key(_km)
 
 
    # 04. encrypt data
    _iv = get_random_bytes(16)
    _encrypted_data = protect_buffer(_plain_data, _kc, _iv)
 
 
    # 05. compute HMAC
    _hmac = compute_hmac_sha256(_ki, _salt, _iv, _encrypted_data)
 
 
    # 06. write encrypted data
    with open(_output_file_path, "wb") as f_out:
        f_out.write(_salt) #8bytes
        f_out.write(_iv) #16bytes
        f_out.write(_encrypted_data) #size-56bytes
        f_out.write(_hmac) #32bytes
    # end with
 
    print("protection done !")
# end main
 
 
if __name__ == "__main__":
    main(sys.argv)
# end if