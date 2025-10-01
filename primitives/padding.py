from random import getrandbits

# The subroutines found in this file pad a stream of bytes to a number of bytes such that it is a multiple of the
# block size and can be feasibly unpadded to return the initial byte stream.

# Pads accoring to PKCS#7 padding.
def PKCS_7_pad(data: bytes, block_size: int) -> bytes:

    # Calculates number of additionaly bytes required before padding this number as a byte an appropriate number of
    # times.
    n: int = block_size - (len(data) % block_size)
    data += bytes([n]) * n
    return data

# Unpads to undo PKCS#7 padding.
def PKCS_7_unpad(data: bytes, block_size: int) -> bytes:

    # The last number
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid Padding Sequence")
    return data[:-n]

# Pads accoring to ANSI X9.23 padding.
def ANSI_X9_23_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += b'\x00' * (n-1) + bytes([n])
    return data

# Unpads to undo ANSI X9.23 padding.
def ANSI_X9_23_unpad(data: bytes, block_size: int) -> bytes:
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    if data[-n:-1] != b'\x00' * (n-1):
        raise ValueError("Invalid Padding Sequence")
    return data[:-n]

# Pads accoring to ISO 10126 padding.
def ISO_10126_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += bytes([getrandbits(8) for i in range(n-1)]) + bytes([n])
    return data

# Unpads to undo ISO 10126 padding.
def ISO_10126_unpad(data: bytes, block_size: int) -> bytes:
    n: int = data[-1]
    if n < 1 or n > len(data) or n > block_size:
        raise ValueError("Invalid Padding Length")
    return data[:-n]

# Pads accoring to ISO/IEC 7816-4:2005 padding.
def ISO_7816_4_pad(data: bytes, block_size: int) -> bytes:
    n: int = block_size - (len(data) % block_size)
    data += b"\x80"+b"\x00"*(n-1)
    return data

# Unpads to undo ISO/IEC 7816-4:2005 padding.
def ISO_7816_4_unpad(data: bytes, block_size: int) -> bytes:
    c = 0
    while data[-1] != 0x80:
        data = data[:-1]
        c += 1
        if c > block_size or c > len(data):
            raise ValueError("Invalid Padding Length")
    return data[:-1]

# Pads accoring to SHA-512 padding.
def SHA_pad(data: int) -> int:
    l: int = data.bit_length()
    if l >= (1 << 64):
        raise ValueError("Message too long.")
    data = data << 1 | 1
    n: int = 448 - (l+1) % 512
    data <<= n + 64
    return data | l