import random
from sympy import nextprime
from typing import Literal
from global_primitives import *
from hashing import SHA2

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
        lN = math.ceil(N.bit_length() / 8.0)

        plaintext_int = int.from_bytes(RSA.OAEP_pad(plaintext, lN))
        ciphertext_int = pow(plaintext_int, e, N)
        ciphertext = ciphertext_int.to_bytes(l)

        return ciphertext

    @staticmethod
    def decrypt(key: tuple[int, int], ciphertext: bytes):
        d, N = key
        l = (N.bit_length() + 7) // 8
        lN = math.ceil(N.bit_length()/8.0)

        ciphertext_int = int.from_bytes(ciphertext)
        plaintext_int = pow(ciphertext_int, d, N)
        plaintext, verification = RSA.OAEP_unpad(plaintext_int.to_bytes(l), lN)

        if verification: return plaintext

    @staticmethod
    def MGF1(seed: bytes, l: int) -> bytes:

        hLen = 64
        if l > hLen*(2<<32):
            raise ValueError("MGF1: Length too long.")
        T = b""
        for c in range(math.ceil(l/hLen)):
            C = c.to_bytes(4, byteorder="big")

            T = T + SHA2("512", seed + C).digest()
        return T[:l]

    @staticmethod
    def OAEP_pad(message: bytes, modulus_length: int, label: bytes=b"") -> bytes:

        k = modulus_length
        hLen = 32
        mLen = len(message)

        """
        RSA Key Size (bits) Max Msg (SHA-256)   Max Msg (SHA-512)
        1024                62                  n/a
        2048                190                 126
        4096                446                 382
        """
        if k == 128 and hLen == 64:
            raise ValueError("SHA512 based OAEP is invalid for 1024 bit RSA.")
        elif mLen > k - 2 * hLen - 2:
            raise ValueError(f"The maximum input size for RSA with {str(k * 8)} bits and SHA{str(hLen * 8)} based padding is {str(k - 2 * hLen - 2)}.")

        PS = b"\x00" * (k - mLen - 2 * hLen - 2)
        lHash = SHA2("256", label).digest()
        DB = lHash + PS + b"\x01" + message
        seed = random.randbytes(hLen)
        dbMask = RSA.MGF1(seed, k - hLen - 1)
        maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))
        seedMask = RSA.MGF1(maskedDB, hLen)
        maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))
        EM = b"\x00" + maskedSeed + maskedDB
        return EM

    @staticmethod
    def OAEP_unpad(encoded_message: bytes, modulus_length: int, label: bytes=b"") -> (bytes, bool   ):
        k = modulus_length
        hLen = 32
        maskedSeed, maskedDB = encoded_message[1:1+hLen], encoded_message[1+hLen:]
        seedMask = RSA.MGF1(maskedDB, hLen)
        seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))
        dbMask = RSA.MGF1(seed, k - hLen - 1)
        DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
        lHash, DB = DB[:hLen], DB[hLen:]
        mLen = k - 2 * hLen -2
        while DB[0] == 0:
            mLen -= 1
            DB = DB[1:]
        b1, M = DB[:1], DB[1:]
        return M, lHash == SHA2("256", label).digest()


ts = set()
pu, pr = RSA.new_key_pair(1024)

for i in range(1000):
    print(i)
    p = random.randbytes(6)

    c = RSA.encrypt(pu, p)

    d = RSA.decrypt(pr, c)

    ts.add(d==p)

print(ts)