from random import getrandbits

def PKCS_7_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += bytes([n]) * n
    return data

def PKCS_7_unpad(data: bytes, block_size: int) -> bytes:
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid Padding Sequence")
    return data[:-n]

def ANSI_X9_23_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += b'\x00' * (n-1) + bytes([n])
    return data

def ANSI_X9_23_unpad(data: bytes, block_size: int) -> bytes:
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    if data[-n:-1] != b'\x00' * (n-1):
        raise ValueError("Invalid Padding Sequence")
    return data[:-n]

def ISO_10126_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += bytes([getrandbits(8) for i in range(n-1)]) + bytes([n])
    return data

def ISO_10126_unpad(data: bytes, block_size: int) -> bytes:
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    return data[:-n]

def ISO_7816_4_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += b"\x80"+b"\x00"*(n-1)
    return data

def ISO_7816_4_unpad(data: bytes, block_size: int) -> bytes:
    c = 0
    while data[-1] != 0x80:
        data = data[:-1]
        c += 1
        if c > block_size or c > len(data):
            raise ValueError("Invalid Padding Length")
    return data[:-1]

def SHA_pad(data: int) -> int:
    l: int = data.bit_length()
    if l >= (1 << 64):
        raise ValueError("Message too long.")
    data = data << 1 | 1
    n: int = 448 - (l+1) % 512
    data <<= n + 64
    return data | l