import sys
from Crypto.Random.random import choice
import string


def genPassword(length, alphabet):
  if length <= 0:
    return ''
  else:
    randPassword = ''
    for i in range(length):
      randPassword += choice(alphabet)
    return randPassword


if __name__ == '__main__':
    if len(sys.argv) !=2:
        print("[ERROR] usage is : {sys.argv[0]} <length>")
        sys.exit(1)

    alphabet = string.ascii_letters + string.digits + string.punctuation
    randPassword = genPassword(int(sys.argv[1]), alphabet)
    print("Generated Password of length "+str(sys.argv[1])+": "+randPassword)
