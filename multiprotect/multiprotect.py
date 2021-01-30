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

#Fonction qui ecrit un buffer dans un fichier
def write_buffer_to_file(buffer: bytes, file: str):
    f_out = open(file, "wb")
    f_out.write(buffer)

#Fonction qui retourne le contenu d'un fichier
def get_file_buffer(file: str):

    if os.path.exists(file):
        _sz = os.path.getsize(file)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        with open(file, "rb") as f_in:
            buffer = f_in.read()
    return buffer

#Fonction qui calcule le SHA256 d'un buffer <---- SHA256(RSA_kpub)
def sha256_buffer(buffer: bytes, chunk_sz=512) -> Optional[bytes]:
    # sha256 ctx init
    sha256_ctx = SHA256.new()
    # read file + update sha256 ctx
    data = buffer.encode()
    sha256_ctx.update(data)
    return sha256_ctx.digest()

#Fonction qui genere une clef AES et un vecteur d'initialisation <---- Kc,IV
def gen_kc_iv():
    # 01. generate symetric key: kc
  kc = get_random_bytes(AES.key_size[2]) # AES.key_size[2] == 32 | 256 bits
  iv = get_random_bytes(AES.block_size) # 16 bytes == 128bits
  return kc,iv

#Fonction qui chiffre la clef et le vecteur d'initialisation <--- RSA_kpub(Kc || IV)
def protect_kv_and_iv(pub_key: bytes, kc: bytes, iv: bytes) -> bytes: 
# 01. encrypt `kc` (256bits) + iv (128 bits) with RSA-2048-OAEP -> wrap_key
  rsa_pub_key = RSA.importKey(pub_key)
  rsa = PKCS1_OAEP.new(rsa_pub_key)
  wrap_key = rsa.encrypt(kc + iv)
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

    list_path_pub_key = []
    data_to_send = b''

# check arguments
    if ((len(argv) < 7) or (((argv[1] != "-e")) and (argv[1] != "-d"))):
        print("Error, usage to encrypt: python {0} -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]".format(argv[0]))
        print("Error, usage to decrypt: python {0} -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>".format(argv[0]))
        sys.exit(1)

# encrypt mode
    if(argv[1] == "-e"):

        #init
        input_file  = argv[2]
        output_file     = argv[3]
        path_my_sign_priv    = argv[4]
        path_my_ciph_pub    = argv[5]

        #get all receiver(s) pub_key
        for i in range(6,len(argv)):
            list_path_pub_key.append(argv[i])
        nb_dest = len(list_path_pub_key)
        print("Nb dest: "+str(nb_dest))

        #generation kc,IV
        kc,iv = gen_kc_iv()

        #for each receiver
        for i in range(nb_dest):
            print("user: "+str(i))
            actual_path_pub_key = list_path_pub_key[i]
            #get actual receiver pub_key
            actual_pub_key = open(actual_path_pub_key).read()
            #compute SHA256() of actual receiver pub_key
            actual_sha = sha256_buffer(actual_pub_key)
            #cipher Kc and IV with pub_key of actual receiver
            wrap_key = protect_kv_and_iv(actual_pub_key,kc,iv)
            #update buffer to send
            data_to_send += (b'\x00' + actual_sha + wrap_key)
        #get input_file buffer
        plain_data = get_file_buffer(input_file)
        #cipher input_file buffer
        C = sym_protect_buffer(plain_data,kc,iv)
        #update buffer to send with Cipher
        data_to_send += (b'\x01' + C)
        #get my priv_key
        my_sign_priv = open(path_my_sign_priv).read()
        #sign buffer to send
        signature = sign_buffer(data_to_send,my_sign_priv)
        #update buffer to send with signature
        data_to_send += signature
        #write buffer to send to output file
        write_buffer_to_file(data_to_send,output_file)

if __name__ == "__main__":
    main(sys.argv)
# end if