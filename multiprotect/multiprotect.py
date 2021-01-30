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
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from typing import Tuple


#----------------------Partie chiffrement--------------------------------------
# 0x00 || SHA256(kpub-1) || RSA_kpub-1(Kc || IV) || ... || 0x00 || SHA256(kpub-N) || RSA_kpub-N(Kc || IV) || 0x01 || C || Sign


#Fonction qui calcule le SHA256 d'un fichier de clef publique <---- SHA256(RSA_kpub)
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

#Fonction qui genere une clef AES et un vecteur d'initialisation <---- Kc,IV
def gen_kc_iv(kc: bytes, iv: bytes):
    # 01. generate symetric key: kc
  kc = get_random_bytes(AES.key_size[2]) # AES.key_size[2] == 32 | 256 bits
  iv = get_random_bytes(AES.block_size) # 16 bytes == 128bits
  return kc,iv

#Fonction qui chiffre la clef et le vecteur d'initialisation <--- RSA_kpub(Kc || IV)
def protect_kv_and_iv(pub_key: bytes, kc: bytes, iv: bytes):
  # 01. encrypt `data` with AES-256-CBC -> encrypted_data
  aes = AES.new(kc, AES.MODE_CBC, iv)
  padded_data = pad(data, AES.block_size)
  encrypted_data = aes.encrypt(padded_data)
 
  # 02. encrypt `kc` (256bits) + iv (128 bits) with RSA-2048-OAEP -> wrap_key
  rsa_pub_key = RSA.importKey(pub_key)
  rsa = PKCS1_OAEP.new(rsa_pub_key)
  wrap_key = rsa.encrypt(kc + iv)
 
  # 03. return kc || iv
  return wrap_key 
 
# Fonction qui chiffre un buffer (AES-CBC-256) <---- C
def sym_protect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    padded_input = pad(buffer, AES.block_size)
    return aes.encrypt(padded_input)

# Fonction qui signe un buffer <---- Sign
def sign_buffer(data: bytes, priv_key: bytes) -> bytes:

  # 01. h = hash(data)
  sha256 = SHA256.new()
  sha256.update(data)
  # IMPORTANT: don't apply digest()
 
  # 02. rsa = create RSA context
  rsa_priv_key = RSA.import_key(priv_key)
  rsa_pss = pss.new(rsa_priv_key)
 
  # 03. sign RSA-2048-PSS with priv_key (h)
  return rsa_pss.sign(sha256)


#----------------------Partie dechiffrement--------------------------------------
#Fonction qui verifie la signature

#Fonction qui dechiffre la clef et le vecteur d'initialisation

# Fonction qui dechiffre un buffer (AES-CBC-256)
def sym_unprotect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(buffer)
    return unpad(decrypted_data, AES.block_size)

def main(argv):
# check arguments
    if ((len(argv) < 7) or (((argv[1] != "-e")) and (argv[1] != "-d"))):
        print("Error, usage to encrypt: python {0} -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]".format(argv[0]))
        print("Error, usage to decrypt: python {0} -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>".format(argv[0]))
        print(argv)
        sys.exit(1)

# end main
 
 
if __name__ == "__main__":
    main(sys.argv)
# end if