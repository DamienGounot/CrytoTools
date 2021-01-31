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
    print("Write to file "+file+": Done !")
#Fonction qui retourne le contenu d'un fichier
def get_file_buffer(file: str):

    if os.path.exists(file):
        _sz = os.path.getsize(file)
        if _sz == 0:
            print("Error: Input file is empty")
            sys.exit(1)
        with open(file, "rb") as f_in:
            buffer = f_in.read()
    else:
        print("error: Input file does not exist")
        sys.exit(1)
    print("Getting content of "+file+" : Done !")
    return buffer

#Fonction qui calcule le SHA256 d'un buffer <---- SHA256(RSA_kpub)
def sha256_buffer(buffer: bytes, chunk_sz=512) -> Optional[bytes]:
    sha256_ctx = SHA256.new()
    data = buffer.encode()
    sha256_ctx.update(data)
    print("Compute SHA256 of public key: Done !")
    return sha256_ctx.digest()

#Fonction qui genere une clef AES et un vecteur d'initialisation <---- Kc,IV
def gen_kc_iv():
  kc = get_random_bytes(AES.key_size[2]) # AES.key_size[2] == 32 | 256 bits
  iv = get_random_bytes(AES.block_size) # 16 bytes == 128bits
  print("Generation of Kc,IV: Done !")
  return kc,iv

#Fonction qui chiffre la clef et le vecteur d'initialisation <--- RSA_kpub(Kc || IV)
def protect_kv_and_iv(pub_key: bytes, kc: bytes, iv: bytes) -> bytes: 
# 01. encrypt `kc` (256bits) + iv (128 bits) with RSA-2048-OAEP -> wrap_key
  rsa_pub_key = RSA.importKey(pub_key)
  rsa = PKCS1_OAEP.new(rsa_pub_key)
  wrap_key = rsa.encrypt(kc + iv)
  print("Cipher (KC || IV) with public key: Done !")
  return wrap_key  
 
# Fonction qui chiffre un buffer (AES-CBC-256) <---- C
def sym_protect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    padded_input = pad(buffer, AES.block_size)
    print("Cipher file content (AES-CBC-256): Done !")
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
  print("Signature with my private key: Done !")
  return rsa_pss.sign(sha256)

#----------------------Partie dechiffrement--------------------------------------
#Fonction qui retourne la signature, et le contenu signé d'un fichier
def extract_from_input_file(input_file_path: str):
    if os.path.exists(input_file_path):
        _sz = os.path.getsize(input_file_path)
        if _sz == 0:
            print("Error: Input file is empty")
            sys.exit(1)
        with open(input_file_path, "rb") as f_in:
            _signed_data = f_in.read(_sz-256)
            _signature = f_in.read(256)
        print("Extract signature and signed data from imput file "+input_file_path+": Done !")
        return _signature, _signed_data

#Fonction qui verifie la signature d'un buffer
def verify_signature(data: bytes, pub_key: bytes,signature: bytes):
    print("Verifying signature of sender...")
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

#Fonction qui retrouve la clef et le vecteur d'initialisation qui nous sont associées
def get_ciphered_kc_iv(input_file_path: str,my_sha256: bytes):
    if os.path.exists(input_file_path):
        _sz = os.path.getsize(input_file_path)
        if _sz == 0:
            print("Error: Input file is empty")
            sys.exit(1)
        with open(input_file_path, "rb") as f_in:
            while(True):
                mark = f_in.read(1)
                if(mark == b'\x00'):
                    actual_sha = f_in.read(32)
                    actual_wrap = f_in.read(256)
                    if(actual_sha == my_sha256):
                        print("Extraction of Cipher(KC || IV): Done !")
                        return actual_wrap

#Fonction qui extrait le contenu chiffré
def extract_ciphered_data(input_file_path: str):
    if os.path.exists(input_file_path):
        _sz = os.path.getsize(input_file_path)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        with open(input_file_path, "rb") as f_in:
            while(True):
                mark = f_in.read(1)
                if(mark == b'\x00'):
                    actual_sha = f_in.read(32)
                    actual_wrap = f_in.read(256)
                else:
                    reste = f_in.read()
                    cipher_data = reste[:-256]
                    print("Extract ciphered Data: Done !")
                    return cipher_data

#Fonction qui dechiffre la clef et le vecteur d'initialisation
def uncipher_kc_iv(wrap: bytes,my_priv_key: bytes):
    rsa_priv_key = RSA.importKey(my_priv_key)
    rsa = PKCS1_OAEP.new(rsa_priv_key)
    wrap_uncrypt = rsa.decrypt(wrap)
    kc = wrap_uncrypt[:32]
    iv = wrap_uncrypt[32:]
    print("Uncipher of KC and IV: Done !")
    return kc,iv

# Fonction qui dechiffre un buffer (AES-CBC-256)
def sym_unprotect_buffer(buffer: bytes, kc: bytes, iv:Optional[bytes]) -> Optional[bytes]:
    aes = AES.new(kc, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(buffer)
    print("Uncipher data (AES-CBC-256): Done !")
    return unpad(decrypted_data, AES.block_size)


#----------------------Partie main----------------------------------------------
def main(argv):

    list_path_pub_key = []
    data_to_send = b''
    print("========== This script has been develop to work with RSA 2048 key size ==========")
 # check arguments
    if ((len(argv) < 6) or (((argv[1] != "-e")) and (argv[1] != "-d"))):
        print("Error, usage to encrypt: python {0} -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]".format(argv[0]))
        print("Error, usage to decrypt: python {0} -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>".format(argv[0]))
        sys.exit(1)

 # encrypt mode
    if(argv[1] == "-e"):
        print("========== Encryption Mode ==========")
        #get all receiver(s) pub_key
        for i in range(5,len(argv)):
            list_path_pub_key.append(argv[i])
        nb_dest = len(list_path_pub_key)
        #generation kc,IV
        kc,iv = gen_kc_iv()
        #for each receiver
        for i in range(nb_dest):
            actual_path_pub_key = list_path_pub_key[i]
            #get actual receiver pub_key
            actual_pub_key = open(actual_path_pub_key).read()
            print("Get public key: "+actual_path_pub_key)
            #compute SHA256() of actual receiver pub_key
            actual_sha = sha256_buffer(actual_pub_key)
            #cipher Kc and IV with pub_key of actual receiver
            wrap_key = protect_kv_and_iv(actual_pub_key,kc,iv)
            #update buffer to send
            data_to_send += (b'\x00' + actual_sha + wrap_key)
            print("Update data to send !")
        #get input_file buffer
        input_file = argv[2]
        plain_data = get_file_buffer(input_file)
        #cipher input_file buffer
        C = sym_protect_buffer(plain_data,kc,iv)
        #update buffer to send with Cipher
        data_to_send += (b'\x01' + C)
        print("Update data to send !")
        #get my priv_key
        path_my_sign_priv = argv[4]
        my_sign_priv = open(path_my_sign_priv).read()
        print("Get my private key: "+path_my_sign_priv)
        #sign buffer to send
        signature = sign_buffer(data_to_send,my_sign_priv)
        #update buffer to send with signature
        data_to_send += signature
        print("Update data to send !")
        #write buffer to send to output file
        output_file = argv[3]
        write_buffer_to_file(data_to_send,output_file)
 # decrypt mode
    if(argv[1] == "-d"):
        print("========== Decryption Mode ==========")
        #get signature and signed_data from input_file
        input_file = argv[2]
        signature,signed_data = extract_from_input_file(input_file)
        #verify signature
        sender_pub_key = open(argv[6]).read()
        print("Get sended public key: "+argv[6])
        verify = verify_signature(signed_data,sender_pub_key,signature)
        if(not verify):
            sys.exit(1)
        else:
            #get my pub_key
            path_my_pub_key = argv[5]
            my_pub_key = open(path_my_pub_key).read()
            print("Get my public key: "+path_my_pub_key)
            #compute SHA256() of my_pub_key
            my_sha = sha256_buffer(my_pub_key)
            #extract my (kc,iv)
            ciphered_kc_iv = get_ciphered_kc_iv(input_file,my_sha)
            #get my priv_key
            path_my_priv_key = argv[4]
            my_priv_key = open(path_my_priv_key).read()
            print("Get my private key: "+path_my_priv_key)
            #get kc and iv
            kc,iv = uncipher_kc_iv(ciphered_kc_iv,my_priv_key)
            #uncipher data
            C = extract_ciphered_data(input_file)
            uncipher_data = sym_unprotect_buffer(C,kc,iv)
            #write data to output file
            output_file = argv[3]
            write_buffer_to_file(uncipher_data,output_file)

if __name__ == "__main__":
    main(sys.argv)