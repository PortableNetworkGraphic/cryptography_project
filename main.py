print(0x428a2f98)

import ctypes

lib = ctypes.CDLL(r"C:\Users\danal\PycharmProjects\cryptography\primitives\cprims.dll")

class RoundState(ctypes.Structure):
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
lib.round1.argtypes = (RoundState, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int)
lib.round1.restype = RoundState

r = lib.round1(RoundState(1,2,3,4,5,6,7,8), 1, 2, 256)
a,b,c,d,e,f,g,h = r.a, r.b, r.c, r.d, r.e, r.f, r.g, r.h
print(a,b,c,d,e,f,g,h)