from hashing import SHA2

def byte_xor(*args: bytes) -> bytes:
    r = 0
    for val in args:
        r ^= int.from_bytes(val, byteorder="big")
    return r.to_bytes(len(args[0]))

def HMAC_SHA2(key: bytes, source: str | bytes, vers: str="256") -> bytes:
    Hi = SHA2(vers=vers)
    Ho = SHA2(vers=vers)
    bl = Hi.kind//4

    if len(key) > bl:
        kd = SHA2(key, vers=vers).digest()
    else:
        kd = key + b"\x00" * (bl-len(key))

    opad = bl * b"\x5c"
    ipad = bl * b"\x36"

    print(bl)
    print(kd, ipad, opad, sep='\n')
    print(len(kd), len(ipad), len(opad))

    Hi.update(byte_xor(kd, ipad))
    Hi.update(source)
    Ho.update(byte_xor(kd, opad))
    Ho.update(Hi.digest().to_bytes(Hi.len//8))
    return Ho.digest()#.to_bytes(Ho.len//8)


print(hex(HMAC_SHA2(b"key", b"The quick brown fox jumps over the lazy dog", vers="512")))