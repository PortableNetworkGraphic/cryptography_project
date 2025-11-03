# The subroutines found in this file pad a stream of bytes to a number of bytes such that it is a multiple of the
# block size and can be feasibly unpadded to return the initial byte stream.
import random
from typing import Literal

from Cython.Compiler.Errors import message


def PKCS7_pad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l: int = len(data) # Length of data)
    n: int = pad_size - (l % pad_size) # Bytes needed to pad
    pad: bytes = n.to_bytes(1) * n # Pad bytes
    return data + pad # Padded data

def PKCS7_unpad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l = len(data) # Length of data
    n = data[-1] # Last byte of the data is the number of padded bytes
    if data[l-n:] != n * n.to_bytes(1): raise ValueError(f"Padding is inconsistent.")
    return data[:l-n] # Data to as long as the data length, minus the padding bytes

def ANSI_pad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l: int = len(data) # Length of data)
    n: int = pad_size - (l % pad_size) # Bytes needed to pad
    pad: bytes = b'\x00' * (n-1) + n.to_bytes(1) # Pad bytes
    return data + pad # Padded data

def ANSI_unpad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l = len(data) # Length of data
    n = data[-1] # Last byte of the data is the number of padded bytes
    if data[l-n:] != b'\x00' * (n-1) + n.to_bytes(1): raise ValueError(f"Padding is inconsistent.") # Check right pad
    return data[:l-n] # Data to as long as the data length, minus the padding bytes

def ISO10126_pad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l: int = len(data) # Length of data)
    n: int = pad_size - (l % pad_size) # Bytes needed to pad
    pad: bytes = random.randbytes(1) * (n-1) + n.to_bytes(1) # Pad bytes
    return data + pad # Padded data

def ISO10126_unpad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size <= 255: raise ValueError(f"Padding Size must be between 1 and 255, not {pad_size}.")
    l = len(data) # Length of data
    n = data[-1] # Last byte of the data is the number of padded bytes
    return data[:l-n] # Data to as long as the data length, minus the padding bytes

def ISO7816_pad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size: raise ValueError(f"Padding Size must be greater than 0, not {pad_size}.")
    l: int = len(data) # Length of data)
    n: int = pad_size - (l % pad_size) # Bytes needed to pad
    pad: bytes = b'\x01' + b'\x00' * (n-1) # Pad bytes
    return data + pad # Padded data

def ISO7816_unpad(data: bytes, pad_size: int) -> bytes:
    if not isinstance(data, bytes): raise TypeError(f"Data must be bytes, not \'{type(data)}\'.")
    if not isinstance(pad_size, int): raise TypeError(f"Padding Size must be int, not \'{type(pad_size)}\'.")
    if not 1 <= pad_size: raise ValueError(f"Padding Size must be greater than 0, not {pad_size}.")

    # While the last byte is zero, remove it byte. When it's not a zero, get rid of the 1 and return. If it isn't a 1,
    # something has gone wrong.
    while data[-1] == 0:
        data = data[:-1]
    if data[-1] == 1:
        return data[:-1]
    else:
        raise ValueError(f"Padding is inconsistent.")

def OAEP_pad(MGF, Hash, hLen: int, k, M: bytes, mLen, L: bytes) -> bytes:
    lHash = Hash(L)
    PS = b"\x00" * (k-mLen*hLen-2)
    DB = lHash + PS + b"\x01" + M
    seed = random.randbytes(hLen)
    dbMask = MGF(seed, k-hLen-1)

    # maskedSeed =