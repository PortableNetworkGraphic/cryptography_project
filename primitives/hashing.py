import hashlib
import math
import os
import random
import string
import sys
from time import perf_counter as pc
import numpy as np
from typing import Literal
import ctypes
import matplotlib.pyplot as plt
from pyinstrument import Profiler

def concatenate(ints: list | tuple, size: int):
    res = 0
    for i in ints:
        res = (res << size) | i
    return res


class SHA256_hash_state(ctypes.Structure):
    _fields_ = [
        ("a", ctypes.c_uint32),
        ("b", ctypes.c_uint32),
        ("c", ctypes.c_uint32),
        ("d", ctypes.c_uint32),
        ("e", ctypes.c_uint32),
        ("f", ctypes.c_uint32),
        ("g", ctypes.c_uint32),
        ("h", ctypes.c_uint32),
    ]

    def out(self):
        return concatenate([self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h], 32)

class SHA512_hash_state(ctypes.Structure):
    _fields_ = [
        ("a", ctypes.c_uint64),
        ("b", ctypes.c_uint64),
        ("c", ctypes.c_uint64),
        ("d", ctypes.c_uint64),
        ("e", ctypes.c_uint64),
        ("f", ctypes.c_uint64),
        ("g", ctypes.c_uint64),
        ("h", ctypes.c_uint64),
    ]

    def out(self):
        return concatenate([self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h], 64)

def SHA2bp(path: str, version: str="256") -> int:
    hl = ctypes.CDLL("./hashing.dll")

    if version == "224":
        initial_state = SHA256_hash_state(0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4)
        hl.SHA256bp.argtypes = [ctypes.POINTER(SHA256_hash_state), ctypes.c_char_p]
        hl.SHA256bp.restypes = None
        hl.SHA256bp(initial_state, path.encode("utf-8"))
        return initial_state.out() >> (256-32)
    elif version == "256":
        initial_state = SHA256_hash_state(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
        hl.SHA256bp.argtypes = [ctypes.POINTER(SHA256_hash_state), ctypes.c_char_p]
        hl.SHA256bp.restypes = None
        hl.SHA256bp(initial_state, path.encode("utf-8"))
        return initial_state.out()
    elif version == "384":
        initial_state = SHA512_hash_state(0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4)
        hl.SHA512bp.argtypes = [ctypes.POINTER(SHA512_hash_state), ctypes.c_char_p]
        hl.SHA512bp.restypes = None
        hl.SHA512bp(initial_state, path.encode("utf-8"))
        return initial_state.out() >> (512-384)
    elif version == "512":
        initial_state = SHA512_hash_state(0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)
        hl.SHA512bp.argtypes = [ctypes.POINTER(SHA512_hash_state), ctypes.c_char_p]
        hl.SHA512bp.restypes = None
        hl.SHA512bp(initial_state, path.encode("utf-8"))
        return initial_state.out()
    elif version == "512/224":
        initial_state = SHA512_hash_state(0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304C48942, 0x3f9d85a86a1d36C8, 0x1112e6ad91d692a1)
        hl.SHA512bp.argtypes = [ctypes.POINTER(SHA512_hash_state), ctypes.c_char_p]
        hl.SHA512bp.restypes = None
        hl.SHA512bp(initial_state, path.encode("utf-8"))
        return initial_state.out() >> (512-224)
    elif version == "512/256":
        initial_state = SHA512_hash_state(0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddC81c52ca2)
        hl.SHA512bp.argtypes = [ctypes.POINTER(SHA512_hash_state), ctypes.c_char_p]
        hl.SHA512bp.restypes = None
        hl.SHA512bp(initial_state, path.encode("utf-8"))
        return initial_state.out() >> (512-256)
    else:
        raise ValueError(f"SHA2 version \"{version}\" is invalid.")


print(hex(SHA2bp(r"C:\Users\danal\Downloads\test.txt")))