import time
import random
import ctypes
import os
import sys

import matplotlib.pyplot as plt
from time import perf_counter as pc
import numpy as np
from hashing import SHA2

def AESencrypt(version: str, input_filepath: str, output_filepath: str, key: int, nonce: int):

    if version not in ["128", "196", "256"]: raise ValueError("AES: Version must be in 128, 196, 256")
    aeslib = ctypes.CDLL(".\\aes.dll")

    if version == "128":
        key_words = [(key >> (32 * (3 - k))) & 0xFFFFFFFF for k in range(4)]
        key_words = (ctypes.c_uint32 * 4)(*key_words)
        aeslib.AES128_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 4, ctypes.c_uint64]
        aeslib.AES128_CTR_encrypt.restypes = None
        aeslib.AES128_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "196":
        key_words = [(key >> (32 * (5 - k))) & 0xFFFFFFFF for k in range(6)]
        key_words = (ctypes.c_uint32 * 6)(*key_words)
        aeslib.AES196_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 6, ctypes.c_uint64]
        aeslib.AES196_CTR_encrypt.restypes = None
        aeslib.AES196_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "256":
        key_words = [(key >> (32 * (7 - k))) & 0xFFFFFFFF for k in range(8)]
        key_words = (ctypes.c_uint32 * 8)(*key_words)
        aeslib.AES256_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 8, ctypes.c_uint64]
        aeslib.AES256_CTR_encrypt.restypes = None
        aeslib.AES256_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

def AESdecrypt(version: str, input_filepath: str, output_filepath: str, key: int, nonce: int):

    if version not in ["128", "196", "256"]: raise ValueError("AES: Version must be in 128, 196, 256")
    aeslib = ctypes.CDLL(".\\aes.dll")

    if version == "128":
        key_words = [(key >> (32 * (3 - k))) & 0xFFFFFFFF for k in range(4)]
        key_words = (ctypes.c_uint32 * 4)(*key_words)
        aeslib.AES128_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 4, ctypes.c_uint64]
        aeslib.AES128_CTR_decrypt.restypes = None
        aeslib.AES128_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "196":
        key_words = [(key >> (32 * (5 - k))) & 0xFFFFFFFF for k in range(6)]
        key_words = (ctypes.c_uint32 * 6)(*key_words)
        aeslib.AES196_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 6, ctypes.c_uint64]
        aeslib.AES196_CTR_decrypt.restypes = None
        aeslib.AES196_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "256":
        key_words = [(key >> (32 * (7 - k))) & 0xFFFFFFFF for k in range(8)]
        key_words = (ctypes.c_uint32 * 8)(*key_words)
        aeslib.AES256_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 8, ctypes.c_uint64]
        aeslib.AES256_CTR_decrypt.restypes = None
        aeslib.AES256_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

inp = r"C:\Users\danal\Downloads\test.txt"
enc = r"C:\Users\danal\Downloads\encryptedshi.bin"
dec = r"C:\Users\danal\Downloads\decryptedshi.txt"

for i in range(250):
    with open(inp, 'wb') as f:
        f.write(random.randbytes(1000))

    h1 = hex(SHA2(inp))

    n = random.getrandbits(64)
    k = random.getrandbits(128)
    AESencrypt('128', inp, enc, k, n)
    AESdecrypt('128', enc, dec, k, n)

    h2 = hex(SHA2(dec))


    if not (h1==h2):
        print(i)
        print(h1, h2)
        print(hex(k), hex(n))
        exit()



"""
for ks in ["128", "196", "256"]:
    x, y = [], []

    for i in range(250):
        print(ks+":"+str(i))

        with open(inp, 'wb') as f:
            f.write(random.randbytes(random.randint(1, 10**8)))

        length = os.path.getsize(inp)

        k = random.getrandbits(int(ks))
        n = random.getrandbits(64)

        t1 = pc()
        AESencrypt(ks, inp, enc, k, n)
        t2 = pc()
        print(t2-t1)
        y.append(t2-t1)
        x.append(length)

    x, y = np.array(x), np.array(y)

    ax.scatter(x, y, color={"128":"#1ba1e2", "196":"#d36363", "256":"yellow"}[ks], label="AES-"+ks, marker='.')

    m = np.polyfit(x, y, 1)
    gradients.append(1/m)
    ax.plot(np.unique(x), np.poly1d(m)(np.unique(x)), color={"128":"blue", "196":"red", "256":"#e3c800"}[ks])

ax.set_ylim(ymin=0)
ax.set_xlim(xmin=0)



ax.legend()
ax.set_xlabel("Number of random bytes")
ax.set_ylabel("Time taken (seconds)")

print(gradients)

plt.show()

"""
