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
  priv = open("private.pem","wb")
  priv.write(rsa.export_key('PEM'))
  priv.close()
  pub = open("public.pem","wb")
  pub.write(rsa_pub.export_key('PEM'))
  pub.close()

def main(argv):
    generate_rsa_keys(2048)

if __name__ == "__main__":
    main(sys.argv)