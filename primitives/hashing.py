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


def SHA2(path: str, version: str="256") -> int:

    hashinglib = ctypes.CDLL("./hashing.dll")

    versions = ["224", "256", "384", "512"]

    if version not in versions:
        raise ValueError(f"SHA2 version \"{version}\" is invalid.")

    out = []
    if version == "224":
        out = (ctypes.c_uint32 * 7)()
        hashinglib.SHA224.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
        hashinglib.SHA224.restypes = None
        hashinglib.SHA224(path.encode("utf-8"), out)
        out = concatenate([out[i] for i in range(len(out))], 32)
    elif version == "256":
        out = (ctypes.c_uint32 * 8)()
        hashinglib.SHA256.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
        hashinglib.SHA256.restypes = None
        hashinglib.SHA256(path.encode("utf-8"), out)
        out = concatenate([out[i] for i in range(len(out))], 32)
    elif version == "384":
        out = (ctypes.c_uint64 * 6)()
        hashinglib.SHA384.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64)]
        hashinglib.SHA384.restypes = None
        hashinglib.SHA384(path.encode("utf-8"), out)
        out = concatenate([out[i] for i in range(len(out))], 64)
    elif version == "512":
        out = (ctypes.c_uint64 * 8)()
        hashinglib.SHA512.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64)]
        hashinglib.SHA512.restypes = None
        hashinglib.SHA512(path.encode("utf-8"), out)
        out = concatenate([out[i] for i in range(len(out))], 64)
    return out


print(hex(SHA2("test.txt", "384")))
print("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
