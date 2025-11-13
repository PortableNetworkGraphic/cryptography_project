import math
import random
import string
import sys
from typing import Literal
import ctypes
from global_primitives import right_rotate as rotr
lib = ctypes.CDLL("./cprims.dll")

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

#lib.SHA512.argtypes = (Hashstate32,  ctypes.c_int, ctypes.c_char_p)
#lib.SHA512.restype = Hashstate64

class SHA2_OLD:

    _input_sizes = {
        "224":64,
        "256":64,
        "384":128,
        "512":128,
        "512-224":128,
        "512-256":128
    }

    initial_hash_values = {
        "224": (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4),
        "256": (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
        "384": (0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4),
        "512": (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179),
        "512-224": (0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1),
        "512-256": (0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2)
    }

    round_constants = {
        "256": (
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ),
        "512": (
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        )

    }

    def __init__(self, version: Literal["224","256","384","512","512-224","512-256"], initial_message: bytes=b""):

        self._message_length = 0
        self._digest = b""
        self.version = version
        self.kind = "256" if self.version in ["224","256"] else "512"
        self.input_size = SHA2_OLD._input_sizes[self.version]
        self.h = SHA2_OLD.initial_hash_values[self.version]
        self.k = SHA2_OLD.round_constants[self.kind]
        self.word_size = self.input_size//2
        self.quotient = 2**self.word_size - 1
        self.update1(initial_message)

    def _f_exp(self, message: bytes, size: int) -> list[int]:
        W = []

        # Completes as many times is needed depending on the specific algorithm being run
        for i in range({32: 64, 64: 80}[size*8]):

            # The first 16 words are simply the message split into 16
            if i <= 15:
                W.append(int.from_bytes(message[size*i:size*(i+1)], byteorder='big'))

            # The remaining words are based off of a piecewise function using the relevant version of Small Sigma 0and 1.
            if 16 <= i:
                x, y = W[i-2], W[i-15]
                if size==4:
                    W.append(
                        ((rotr(x, 17, 32) ^ rotr(x, 19, 32) ^ (x >> 10))
                         + W[i-7]
                         + (rotr(y, 7, 32) ^ rotr(y, 18, 32) ^ (y >> 3))
                         + W[i-16]) & self.quotient)
                elif size==8:
                    W.append(
                        ((rotr(x, 19, 64) ^ rotr(x, 61, 64) ^ (x >> 6))
                         + W[i-7]
                         + (rotr(y, 1, 64) ^ rotr(y, 8, 64) ^ (y >> 7))
                         + W[i-16]) & self.quotient)

        return W

    def SHA_pad(self, data: bytes, pad_size: int, l: int = None) -> bytes:
        if pad_size not in (64, 128): raise ValueError("Size must be 64 or 128")
        if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
        if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
        if pad_size not in [64, 128]: raise ValueError(f"Padding Size must be 512 or 1024 bits, not {pad_size}.")
        r = {64: 56, 128: 112}[pad_size]
        l = self._message_length
        if l > 2 ** pad_size: raise ValueError("Data must be less than 2^64 bits.")
        data += b"\x80"
        while len(data) % pad_size != r: data += b"\x00"
        return data + l.to_bytes(pad_size - r)

    def round1(self, a:int, b:int, c:int, d:int, e:int, f:int, g:int, h:int, Wi:int, Ki:int):

        q = self.quotient
        vers = 256 if self.version in ["224","256"] else 512

        # Selects the appropriate versions of big sigma for the algorithm
        if vers not in [256, 512]: raise ValueError("Version must be valid")
        CH = (e & f) ^ (~e & g)
        if vers == 256:
            # Maths
            S1 = lib.rotr(e, 6, 32) ^ lib.rotr(e, 11, 32) ^ lib.rotr(e, 25, 32)
            t1 = (Wi + Ki + h + CH + S1) & q
            S0 = lib.rotr(a, 2, 32) ^ lib.rotr(a, 13, 32) ^ lib.rotr(a, 22, 32)
        else:
            # Maths
            S1 = lib.rotr(e, 14, 64) ^ lib.rotr(e, 18, 64) ^ lib.rotr(e, 41, 64)
            t1 = (Wi + Ki + h + CH + S1) & q
            S0 = lib.rotr(a, 28, 64) ^ lib.rotr(a, 34, 64) ^ lib.rotr(a, 39, 64)

        t2 = (((a & b) ^ (a & c) ^ (b & c)) + S0) & q
        h = g
        g = f
        f = e
        e = (t1 + d) & q
        d = c
        c = b
        b = a
        a = (t1 + t2) & q
        return a,b,c,d,e,f,g,h

    # Adds message to digest and updates hash values as long as the message is long enough
    def update1(self, message: bytes= b"") -> None:
        k = self.k
        _is = self.input_size
        _digest = self._digest
        _digest += message
        self._message_length += len(message) * 8

        # for each chunk, expands chunk to words and performs a number of rounds of processing on them.
        while len(_digest) >= _is:

            chunk = _digest[:_is]
            _digest = _digest[_is:]

            w = self._f_exp(chunk, _is//16)

            ht = self.h
            for i in range({64: 64, 128: 80}[_is]):
                pass # ht = lib.round1(SHA512State(*ht), w[i], k[i], int(self.kind)).as_tuple()
            self.h = tuple([(ht[i] + self.h[i]) % 2**self.word_size for i in range(8)])
        self._digest = _digest

    # Pads the remaining message and updates using them before concatenating the hash values together and outputting them
    def digest(self) -> int:

        saved_digest, saved_length, saved_h = self._digest, self._message_length, self.h

        self._digest = self.SHA_pad(self._digest, self.input_size)
        self.update1()

        hash_value = 0
        if self.version == "224":
            for hi in self.h[:7]:
                hash_value = (hash_value << self.word_size) | hi
        elif self.version in ["256", "512"]:
            for hi in self.h:
                hash_value = (hash_value << self.word_size) | hi
        elif self.version == "384":
            for hi in self.h[:6]:
                hash_value = (hash_value << self.word_size) | hi
        elif self.version == "512-224":
            for hi in self.h:
                hash_value = (hash_value << self.word_size) | hi
        elif self.version == "512-256":
            for hi in self.h:
                hash_value = (hash_value << self.word_size) | hi

        self._digest, self._message_length, self.h = saved_digest, saved_length, saved_h

        if self.version == "512-224":
            hash_value >>= (512 - 224)
        elif self.version == "512-256":
            hash_value >>= (512 - 256)
        return hash_value

class SHA2_NEW:

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

    upper_input_size = 2 ** 8

    def __init__(self, version: str):

        # Ensure the version selected is valid.
        if version not in SHA2_NEW.versions:
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
        self.buffer: bytes = b""
        self.message_length = 0
        self.hash_state = SHA2_NEW.initial_hash_values[version]
        self.hash_state = Hashstate32(self.hash_state) if self.kind == "256" else Hashstate64(self.hash_state)
        self.quotient = 2**self.word_size - 1

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
        if n_chunks is None: n_chunks = SHA2_NEW.upper_input_size // self.hash_input_size
        if len(message) != n_chunks*self.hash_input_size or len(message) == 0:
            raise ValueError("c_update")
        #                                Hash State     , n_chunks, c bytes
        if self.kind == "256":
            c_msg = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
            self.hash_state = lib.SHA256(self.hash_state, n_chunks, c_msg)

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
            self.c_update(self.buffer[i*SHA2_NEW.upper_input_size:(i+1)*SHA2_NEW.upper_input_size])

        self.buffer = self.buffer[un * SHA2_NEW.upper_input_size:]

        if ln:
            self.c_update(self.buffer[:self.hash_input_size*ln], ln)

        self.buffer = self.buffer[self.hash_input_size*ln:]

    def digest(self) -> int:

        pad = self.SHA_pad(self.buffer, self.hash_input_size)
        self.c_update(pad, len(pad)//self.hash_input_size)

        digest = 0
        if self.kind == "256":
            for hi in self.hash_state.as_tuple():
                digest = (digest << self.word_size*8) | hi


        return digest



ts = set()
st = random.randbytes(1000)
import hashlib

for i in range(1000):
    s = SHA2_NEW("256")
    s.update(st)

    ts.add(hex(s.digest()) == hex(int.from_bytes(hashlib.sha256(st).digest())))

print(ts)

"""def func_test(func, col):
    times = []
    for i in range(100):
        l = random.randint(1, 10**4)
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
"""
# f, ax = plt.subplots(1)

# ax.legend(["initial code"])
# ax.set_xlabel("Number of random bytes")
# ax.set_ylabel("Time taken (seconds)")

# plt.show()