import os
import random

from primitives.aes import AES
from hashing import SHA2

def encrypt_file(source: str, key: bytes, key_len: int, nonce: bytes, authmethod: str, filedest: str, newname: str) -> None:
    fnl = len(newname)
    fn, ext = newname.split('.', 1)
    fn = fn.encode()

    tempfile = rf"C:\Users\danal\PycharmProjects\cryptography_project\primitives\temp\{''.join([chr(random.randint(65, 91)) for i in range(8)])}.{ext}"
    nbytes = AES(key, key_len * 8, nonce).encrypt_file(source, tempfile)

    with open(filedest+"\\"+newname, "wb") as f, open(tempfile, 'rb') as tf:
        f.write(fnl.to_bytes(2, "big"))
        f.write(newname.encode())
        f.write(nbytes.to_bytes(8, "big"))
        while chunk := tf.read(2**19):
            f.write(chunk)
        f.write(b":3")


    with open(filedest + "\\" + newname, "rb") as f:
        fnl = int.from_bytes(f.read(2), "big")
        fn = f.read(fnl).decode()
        nbytes = int.from_bytes(f.read(8), "big")

        print(fnl, fn, nbytes)
        while chunk := f.read(min(nbytes, 2**19)):
            nbytes = max(nbytes - 2 ** 19, 0)
            print(chunk)

        print(f.read())




s = r"C:\Users\danal\PycharmProjects\cryptography_project\primitives\test.txt"
d = r"C:\Users\danal\PycharmProjects\cryptography_project\primitives"
kl = 128//8
k = os.urandom(kl)
nonce = os.urandom(64)
encrypt_file(s, k, kl, nonce, "RSA", d, "test2.txt")

p = "test.txt"
c = "test2.txt"
d = "test3.txt"

AES(k, kl * 8, nonce).encrypt_file(p, c)
