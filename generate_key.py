import sys
import binascii
from Crypto.Random import get_random_bytes

def genKey(lenght):
  if lenght <= 0:
    return b''
  else:  
    key = get_random_bytes(lenght)
    return key


if __name__ == '__main__':
    if len(sys.argv) !=2:
        print("[ERROR] usage is : {sys.argv[0]} <length>")
        sys.exit(1)

    key = genKey(int(sys.argv[1]))
    print("Generated "+str(sys.argv[1])+" Bytes")
    print(binascii.hexlify(key).decode())