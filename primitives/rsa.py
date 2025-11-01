import random
from pydoc import plaintext

from sympy import nextprime
from typing import Literal
from global_primitives import *

class RSA:

    @staticmethod
    def new_key_pair(size: Literal[1024, 2048, 4096]) -> tuple[tuple[int, int], tuple[int, int]]:
        e = 65537
        p, q, lambdaN = None, None, 0

        while lambdaN < e or euclidean_algorithm(e, lambdaN) != 1:

            # Generate random prime numbers
            p = nextprime(random.getrandbits(size//2))
            q = nextprime(random.getrandbits(size//2))

            lambdaN = ((p - 1) * (q - 1)) // euclidean_algorithm(p - 1, q - 1)

        d = extended_euclidean_algorithm_x(lambdaN, e) % lambdaN
        N = p * q

        return (e, N), (d, N)

    @staticmethod
    def encrypt(key: tuple[int, int], plaintext: bytes) -> bytes:
        e, N = key
        l = (N.bit_length() + 7) // 8

        plaintext_int = int.from_bytes(plaintext)
        ciphertext_int = pow(plaintext_int, e, N)
        ciphertext = ciphertext_int.to_bytes(l)

        return ciphertext

    @staticmethod
    def decrypt(key: tuple[int, int], ciphertext: bytes):
        d, N = key
        l = (N.bit_length() + 7) // 8

        ciphertext_int = int.from_bytes(ciphertext)
        plaintext_int = pow(ciphertext_int, d, N)
        plaintext = plaintext_int.to_bytes(l)

        return plaintext



p, s = RSA.new_key_pair(1024)
print(p)
print(s)

m = b"McLovin"
print(m)
print(RSA.decrypt(s, RSA.encrypt(p, m)))