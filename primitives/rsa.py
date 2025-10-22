from sympy import randprime

class RSA:
    def __init__(self, public_key: [tuple[int, int]], private_key: [tuple[int, int]]):
        if public_key is None and private_key is None:
           public_key, private_key

    @staticmethod
    def new_key_pair(size: [1024, 2048, 4096]):
        p, q = randprime(2**(size-1), 2**size)
        e = 65537
        N = p * q
        
