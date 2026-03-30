import os
import random
from primitives.aes import AES
from primitives.rsa import RSA
from primitives.hashing import SHA2, HMAC_SHA2

def encrypt_sym_by_asym(key, rsa_keys: list[tuple[int, int]], key_length: int=2048):
    encrypted_keys = []
    for rsa_key in rsa_keys:
        keybytes = RSA.encrypt(rsa_key, key).rjust(key_length//8, b"\x00")
        encrypted_keys.append((key_length//8).to_bytes(4) + keybytes)
    return encrypted_keys

def encrypt_file(source: str, rsa_keys: list[tuple[int, int]], key_len: int, nonce: bytes, authmethod: str, filedest: str, newname: str, signature_key: tuple[int, int] | None=None) -> True:
    fnl = len(newname)
    fn, ext = newname.split('.', 1)
    fn = fn.encode()

    key = os.urandom(key_len)
    encrypted_keys = encrypt_sym_by_asym(key, rsa_keys, 2048)

    tempfile = rf"C:\Users\danal\PycharmProjects\cryptography_project\primitives\temp\{''.join([chr(random.randint(65, 91)) for i in range(8)])}.{ext}"
    nbytes = AES(key, key_len * 8, nonce).encrypt_file(source, tempfile)
    if authmethod.lower() == "rsa":
        if type(signature_key) != type((1,1)):
            exit("errrrror")
        authbytes = RSA.encrypt(signature_key, SHA2(source).digest()).rjust(2048//8)
        authmethod = b"rs"
    elif authmethod.lower() == "hmac":
        authbytes = HMAC_SHA2(key, source)
        authmethod = b"hm"
    else:
        authbytes = b""
        authmethod = b"\x00\x00"

    with open(filedest+"\\"+newname, "wb") as f, open(tempfile, 'rb') as tf:
        f.write(fnl.to_bytes(2, "big"))
        f.write(newname.encode())
        f.write(len(encrypted_keys).to_bytes(1))
        for rsakey in encrypted_keys:
            f.write(rsakey)

        f.write(nbytes.to_bytes(8, "big"))
        f.write(nonce)
        f.write(key_len.to_bytes(2))
        while chunk := tf.read(2**19):
            f.write(chunk)
        f.write(authmethod+authbytes)

    return True

def decrypt_file(source: str, rsa_key, decrypt_dest: str, signature_key: tuple[int, int] | None=None) -> True:

    with open(source, "rb") as rf:

        fnl = int.from_bytes(rf.read(2))
        fname = rf.read(fnl).decode()
        numkeys = int.from_bytes(rf.read(1))
        key = None
        for i in range(numkeys):
            rsaklen = int.from_bytes(rf.read(4))
            rsakey = rf.read(rsaklen)
            decrypted_sym_key_test, verified = RSA.decrypt(rsa_key, rsakey)

            if verified:

                key = decrypted_sym_key_test


        if not key: exit("erorr")

        nbytes = int.from_bytes(rf.read(8))
        nonce = rf.read(8)
        klen = int.from_bytes(rf.read(2)) * 8
        nbytes_counter = nbytes

        with open(decrypt_dest, 'wb') as df:
            while nbytes_counter > 0:
                chunk = rf.read(min(nbytes_counter, 2**19))
                decchunk, nbdec = AES(key, klen, nonce).encrypt_bytes(chunk)
                nbytes_counter -= nbdec
                df.write(decchunk)
        authmethod = rf.read(2)
        if authmethod == b"\x00\x00":
            return True
        elif authmethod == b"hm":
            observed_hmac = rf.read(256//8)
            expected_hmac = HMAC_SHA2(key, decrypt_dest)
            return observed_hmac == expected_hmac
        elif authmethod == b"rs":
            observed_sig = RSA.decrypt(signature_key, rf.read(2048//8))[0]
            expected_sig = SHA2(decrypt_dest).digest()
            return observed_sig == expected_sig
        return False