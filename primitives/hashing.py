import os
import copy
import random
import pyinstrument
import hashlib
from padding import SHA_pad
import ctypes
import matplotlib.pyplot as plt
import numpy as np
from time import perf_counter as pc

def concatenate(ints: list | tuple, size: int):
    res = 0
    for i in ints:
        res = (res << size) | i
    return res

class SHA256_ctx(ctypes.Structure):
    _fields_ = [
        ("h", ctypes.c_uint32 * 8),
        ("buffer", ctypes.c_uint8 * 64),
        ("mlen", ctypes.c_uint64),
        ("blen", ctypes.c_size_t)
    ]

    def out(self):
        return concatenate([int(i) for i in self.h], 32)

class SHA512_ctx(ctypes.Structure):
    _fields_ = [
        ("h", ctypes.c_uint64 * 8),
        ("buffer", ctypes.c_uint8 * 128),
        ("mlen", ctypes.c_uint64 * 2),
        ("blen", ctypes.c_size_t)
    ]

    def out(self):
        return concatenate([int(i) for i in self.h], 64)

class SHA2:

    def __init__(self, initial_data: bytes|str=b"", vers: str="256", _chunksize: int=1024*512):

        self._chunksize = _chunksize

        self.vers = vers
        self.lib = ctypes.CDLL("./hashing2.dll")
        self.kind = 256 if vers in ("224", "256") else 512
        self.len = int(vers[-3:])

        if self.kind == 256:

            self.ctx = SHA256_ctx()

            self.init = self.lib.sha256_init
            self.init.argtypes = [ctypes.POINTER(SHA256_ctx), ctypes.c_size_t]
            self.init.restypes = None

            self.updatectx = self.lib.sha256_updatectx
            self.updatectx.argtypes = [ctypes.POINTER(SHA256_ctx), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            self.updatectx.restypes = None

            self.digestctx = self.lib.sha256_digest
            self.digestctx.argtypes = [ctypes.POINTER(SHA256_ctx)]
            self.digestctx.restypes = None

        else:

            self.ctx = SHA512_ctx()

            self.init = self.lib.sha512_init
            self.init.argtypes = [ctypes.POINTER(SHA512_ctx), ctypes.c_size_t]
            self.init.restypes = None

            self.updatectx = self.lib.sha512_updatectx
            self.updatectx.argtypes = [ctypes.POINTER(SHA512_ctx), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            self.updatectx.restypes = None

            self.digestctx = self.lib.sha512_digest
            self.digestctx.argtypes = [ctypes.POINTER(SHA512_ctx)]
            self.digestctx.restypes = None

        self.init(self.ctx, self.len)

        self.update(initial_data)

    def update(self, source: str | bytes):
        if isinstance(source, bytes):
            buf = (ctypes.c_uint8 * len(source))(*source)
            self.updatectx(self.ctx, buf, len(buf))
        else:
            with open(source, 'rb') as f:
                buf = (ctypes.c_uint8 * self._chunksize)()
                while chunk := f.read(self._chunksize):
                    n = len(chunk)
                    ctypes.memmove(buf, chunk, n)
                    self.updatectx(self.ctx, buf, n)

    def digest(self):
        temp = copy.deepcopy(self.ctx)

        self.digestctx(temp)

        return temp.out() >> (self.kind - self.len)

"""
for name, size, col, csize in (("512", 512, "#dc7a62", 1024*512), ("512", 512, "green", 1024),):#(("224", 224, "red"), ("256", 256, "orange"), ("384", 384, "yellow"), ("512", 512, "green"), ("512/224", 224, "blue"), ("512/256", 256, "pink")):

    x, y = [], []
    for i in range(100):

        with open("test.txt", 'wb') as f:
            f.write(random.randbytes(random.randint(1, round(10**6))))
            if i % 25 == 0:
                print(name, i)

        length = os.path.getsize("test.txt")

        t1 = pc()
        SHA2("test.txt", vers=name, _chunksize=csize).digest()
        t2 = pc()
        y.append(t2 - t1)

        x.append(length)

    x, y = np.array(x), np.array(y)

    ax.scatter(x, y, color=col, label=name, marker='.')

    m = np.polyfit(x, y, 1)
    ax.plot(np.unique(x), np.poly1d(m)(np.unique(x)), color=col)

    print(round(m[0]**-1)//(10**6))

ax.legend()
ax.set_ylim(ymin=0)
ax.set_xlim(xmin=0)
plt.xlabel("Bytes (B)")
plt.ylabel("Time (s)")

plt.show()"""