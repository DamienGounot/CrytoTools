import sys
import string

from Crypto.Random.random import choice


def generate_password(length: int, alphabet: str) -> str:
    # check length
    if length <= 0:
        return ''
    else:
        password = ''
        for i in range(length):
            password += choice(alphabet)
        return password
# end generate_password


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <password_length>')
        sys.exit(1)
    # else: generate random buffer of lenght sys.argv[1]
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = generate_password(int(sys.argv[1]), alphabet)
    print(password)
    sys.exit(0)