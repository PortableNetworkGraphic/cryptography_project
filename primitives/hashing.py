import hashlib
import math
import random
import string
import sys
from time import perf_counter as pc
import numpy as np
from typing import Literal
import ctypes
lib = ctypes.CDLL("./hashing_prims.dll")
import matplotlib.pyplot as plt
from pyinstrument import Profiler

class Hashstate32(ctypes.Structure):
    _fields_ = [("h", ctypes.c_uint32 * 8)]

    def as_tuple(self):
        return [self.h[i] for i in range(8)]

class Hashstate64(ctypes.Structure):
    _fields_ = [("h", ctypes.c_uint64 * 8)]

    def as_tuple(self):
        return [self.h[i] for i in range(8)]

#                      Hash State , num chunks  , chunk bytes
lib.SHA256.argtypes = (Hashstate32, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte))
lib.SHA256.restype = Hashstate32

lib.SHA512.argtypes = (Hashstate64, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte))
lib.SHA512.restype = Hashstate64

class SHA2:

    versions = ["224", "256", "384", "512", "512/224", "512/256"]

    # The initial eight hash values.
    initial_hash_values = {
        "224": (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4),
        "256": (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
        "384": (0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4),
        "512": (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179),
        "512/224": (0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1),
        "512/256": (0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2)
    }

    upper_input_size = 10 * 2 ** 20

    def __init__(self, version: str, initial_buffer: bytes=b""):

        # Ensure the version selected is valid.
        if version not in SHA2.versions:
            raise ValueError("Error: Invalid SHA version")

        self.kind = "256" if version in ["224", "256"] else "512"

        # Assign various constants depending on the version.
        if self.kind == "256":
            self.word_size = 4
            self.hash_input_size = 64
            self.round_num = 64
        elif self.kind == "512":
            self.word_size = 8
            self.hash_input_size = 128
            self.round_num = 80
        self.version = version
        self.output_size = int(version[-3:])//8
        self.buffer = initial_buffer
        self.message_length = len(initial_buffer)
        self.hash_state = SHA2.initial_hash_values[version]
        self.hash_state = Hashstate32(self.hash_state) if self.kind == "256" else Hashstate64(self.hash_state)
        self.quotient = 2**self.word_size - 1
        self.update(b"")

    def SHA_pad(self, data: bytes, pad_size: int) -> bytes:
        if pad_size not in (64, 128): raise ValueError("Size must be 64 or 128")
        if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
        if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
        if pad_size not in [64, 128]: raise ValueError(f"Padding Size must be 512 or 1024 bits, not {pad_size}.")
        r = {64: 56, 128: 112}[pad_size]
        l = self.message_length * 8
        if l > 2 ** pad_size: raise ValueError("Data must be less than 2^64 bits.")
        data += b"\x80"
        while len(data) % pad_size != r: data += b"\x00"
        return data + l.to_bytes(pad_size - r, "big")

    def c_update(self, message: bytes, n_chunks: int = None) -> None:
        if n_chunks is None: n_chunks = SHA2.upper_input_size // self.hash_input_size
        if len(message) != n_chunks*self.hash_input_size or len(message) == 0:
            raise ValueError("c_update")
        #                                Hash State     , n_chunks, c bytes
        c_msg = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
        if self.kind == "256":
            self.hash_state = lib.SHA256(self.hash_state, n_chunks, c_msg)
        else:
            self.hash_state = lib.SHA512(self.hash_state, n_chunks, c_msg)

    def update(self, message: bytes):

        # Updates the buffer and message length with the new mesage.
        self.buffer += message
        self.message_length += len(message)
        bl = len(self.buffer)

        # Calculates the number of full upper inputs are to be fed into the c update.
        un = bl // self.upper_input_size
        # Calculates the number of
        ln = (bl % self.upper_input_size) // self.hash_input_size

        for i in range(un):
            self.c_update(self.buffer[i * SHA2.upper_input_size:(i + 1) * SHA2.upper_input_size])

        self.buffer = self.buffer[un * SHA2.upper_input_size:]

        if ln:
            self.c_update(self.buffer[:self.hash_input_size*ln], ln)

        self.buffer = self.buffer[self.hash_input_size*ln:]

    def digest(self) -> bytes:

        pad = self.SHA_pad(self.buffer, self.hash_input_size)
        temp_hs = self.hash_state
        self.c_update(pad, len(pad)//self.hash_input_size)

        digest = 0

        if self.version == "224":
            for hi in self.hash_state.as_tuple()[:7]:
                digest = (digest << self.word_size*8) | hi
        elif self.version == "384":
            for hi in self.hash_state.as_tuple()[:6]:
                digest = (digest << self.word_size*8) | hi
        else:
            for hi in self.hash_state.as_tuple():
                digest = (digest << self.word_size*8) | hi
            if self.version == "512/224":
                digest >>= 512 - 224
            elif self.version == "512/256":
                digest >>= 512 - 256



        self.hash_state = temp_hs

        return digest.to_bytes(self.output_size, byteorder="big")

"""def func_test(func, col):
    times = []
    for i in range(10):
        print(i)
        l = random.randint(1, 10**8)
        m = random.randbytes(l)
        t1 = pc()
        func(m)
        t2 = pc()
        times.append((l, t2-t1))

    print(times)


    x, y = [], []
    for size, time in times:
        x.append(size)
        y.append(time)

    x, y = np.array(x), np.array(y)
    print(np.polyfit(x,y, 1)[0]**-1)

    ax.scatter(x, y, color=col)
    ax.set_ylim(ymin=0)
    ax.set_xlim(xmin=0)


f, ax = plt.subplots(1)


func_test(SHA2_NEW("512").update, "blue")
func_test(hashlib.sha512, "red")




ax.legend(["My SHA512", "Hashlib 512"])
ax.set_xlabel("Number of random bytes")
ax.set_ylabel("Time taken (seconds)")

plt.show()"""