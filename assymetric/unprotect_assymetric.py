import sys
import os
 
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
 
from typing import Tuple
 
 
 
def unprotect_buffer(data: bytes,wrap: bytes, priv_key: bytes) -> bytes:

    # 01. Get wrap , uncipher it and extrat Kc and iv
    rsa_priv_key = RSA.importKey(priv_key)
    rsa = PKCS1_OAEP.new(rsa_priv_key)
    wrap_uncrypt = rsa.decrypt(wrap)
    kc = wrap_uncrypt[:32]
    iv = wrap_uncrypt[32:]

    # 02. decrypt `data` with AES-256-CBC -> uncipher_data
    aes = AES.new(kc, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(data)

    # 03. return uncipher data
    return unpad(decrypted_data, AES.block_size)

 
def verify_signature(data: bytes, pub_key: bytes,signature: bytes):
    sha256 = SHA256.new()
    sha256.update(data)

    rsa_pub_key = RSA.import_key(pub_key)
    rsa_pss = pss.new(rsa_pub_key)
    try:
        rsa_pss.verify(sha256, signature)
        print("The signature is authentic.")
        return True
    except (ValueError, TypeError):
        print("The signature is not authentic.")
        return False


def main(argv):
    # 00. check arguments
    if len(argv) != 5:
        print("usage: {0} <private_key_receiver> <public_key_sender> <input_file> <output_file>".format(argv[0]))
        sys.exit(1)
    private_key_receiver = argv[1]
    public_key_sender  = argv[2]
    input_file_path     = argv[3]
    output_file_path    = argv[4]
 
 
    # 01. read input file
    _cipher_data = b''
    if os.path.exists(input_file_path):
        _sz = os.path.getsize(input_file_path)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        with open(input_file_path, "rb") as f_in:
            _wrap_key = f_in.read(256)
            _cipher_data = f_in.read(_sz-512)
            _signature = f_in.read(256)
        _cipher = _wrap_key +_cipher_data
 
    # 02. init RSA contexts
    rsa_dec_priv_pem = open(private_key_receiver).read()
    rsa_sign_pub_pem = open(public_key_sender).read()

    # 03. verify signature
    if(verify_signature(_cipher, rsa_sign_pub_pem,_signature)):
        print("Signature is Ok ---> uncipher data")

        # 04. unprotect cipher_data
        uncipher_data = unprotect_buffer(_cipher_data,_wrap_key, rsa_dec_priv_pem)
        
        # 05. write file
        with open(output_file_path, "wb") as f_out:
            f_out.write(uncipher_data)
        print("uncipher done !")        
    else:
        print("Error: Signature is Ko ---> Abort")
# end main
 
if __name__ == "__main__":
    main(sys.argv)
# end if