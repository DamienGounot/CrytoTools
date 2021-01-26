import sys
import binascii

from Crypto.Random import get_random_bytes


def generate_random(length: int) -> bytes:
    # check length
    if length <= 0:
        return b''
    else:
        return get_random_bytes(length)
# end generate_random


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <key_length_in_bytes>')
        sys.exit(1)
    # else: generate random buffer of lenght sys.argv[1]
    rand = generate_random(int(sys.argv[1]))
    print(f'{binascii.hexlify(rand).decode()}')
    sys.exit(0)
