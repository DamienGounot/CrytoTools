import sys
import os
 
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
 
from typing import Tuple
 
# Fonction qui genere des bicles RSA
def generate_rsa_keys(bits_length: int):
  rsa = RSA.generate(bits_length)
  rsa_pub = rsa.publickey()
  return rsa.export_key('PEM'), rsa_pub.export_key('PEM')
 
 
def generate_rsa_obj_keys(in_bits_length: int) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    rsa_private: RSA.RsaKey = RSA.generate(in_bits_length)
    rsa_public: RSA.RsaKey = rsa_private.publickey()
    return rsa_private, rsa_public
 
 
# Fonction qui protege en Integrite un fichier == Signature
def sign_buffer(data: bytes, priv_key: bytes) -> bytes:
  """
  priv_key = content of PEM file
  """
  # 01. h = hash(data)
  sha256 = SHA256.new()
  sha256.update(data)
  # IMPORTANT: don't apply digest()
 
  # 02. rsa = create RSA context
  rsa_priv_key = RSA.import_key(priv_key)
  rsa_pss = pss.new(rsa_priv_key)
 
  # 03. sign RSA-2048-PSS with priv_key (h)
  return rsa_pss.sign(sha256)
 
 
def protect_buffer(data: bytes, pub_key: bytes) -> bytes:
  # 01. generate symetric key: kc
  kc = get_random_bytes(AES.key_size[2]) # AES.key_size[2] == 32 | 256 bits
 
  # 02. encrypt `data` with AES-256-CBC -> encrypted_data
  iv = get_random_bytes(AES.block_size) # 16 bytes == 128bits
  aes = AES.new(kc, AES.MODE_CBC, iv)
  padded_data = pad(data, AES.block_size)
  encrypted_data = aes.encrypt(padded_data)
 
  # 03. encrypt `kc` (256bits) + iv (128 bits) with RSA-2048-OAEP -> wrap_key
  # wrap_key = RSA.encrypt( kc || iv )
  rsa_pub_key = RSA.importKey(pub_key)
  rsa = PKCS1_OAEP.new(rsa_pub_key)
  wrap_key = rsa.encrypt(kc + iv)
 
  # 04. return wrap_key || encrypted_data
  return wrap_key + encrypted_data
 
 
def main(argv):
    # 00. check arguments
    if len(argv) != 5:
        print("usage: {0} <public_key_receiver> <private_key_sender> <input_file> <output_file>".format(argv[0]))
        sys.exit(1)
    public_key_receiver = argv[1]
    private_key_sender  = argv[2]
    input_file_path     = argv[3]
    output_file_path    = argv[4]
 
 
    # 01. read input file
    plain_data = b''
    if os.path.exists(input_file_path):
        _sz = os.path.getsize(input_file_path)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        with open(input_file_path, "rb") as f_in:
            plain_data = f_in.read()
 
 
    # 02. init RSA contexts
    rsa_enc_pub_pem = open(public_key_receiver).read()
    rsa_sign_priv_pem = open(private_key_sender).read()
 
 
    # 03. protect plain_data
    encrypted_data = protect_buffer(plain_data, rsa_enc_pub_pem)
 
 
    # 04. signature
    signature = sign_buffer(encrypted_data, rsa_sign_priv_pem)
 
 
    # 05. write file
    with open(output_file_path, "wb") as f_out:
        f_out.write(encrypted_data)
        f_out.write(signature)
 
 
    print("protection done !")
# end main
 
 
if __name__ == "__main__":
    main(sys.argv)