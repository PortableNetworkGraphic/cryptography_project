import ctypes

def AESencrypt(version: str, input_filepath: str, output_filepath: str, key: int, nonce: int):

    if version not in ["128", "196", "256"]: raise ValueError("AES: Version must be in 128, 196, 256")
    aeslib = ctypes.CDLL(".\\aes.dll")

    if version == "128":
        key_words = [(key >> (32 * (3 - k))) & 0xFFFFFFFF for k in range(4)]
        key_words = (ctypes.c_uint32 * 4)(*key_words)
        aeslib.AES128_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 4, ctypes.c_uint64]
        aeslib.AES128_CTR_encrypt.restypes = None
        aeslib.AES128_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "196":
        key_words = [(key >> (32 * (5 - k))) & 0xFFFFFFFF for k in range(6)]
        key_words = (ctypes.c_uint32 * 6)(*key_words)
        aeslib.AES196_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 6, ctypes.c_uint64]
        aeslib.AES196_CTR_encrypt.restypes = None
        aeslib.AES196_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "256":
        key_words = [(key >> (32 * (7 - k))) & 0xFFFFFFFF for k in range(8)]
        key_words = (ctypes.c_uint32 * 8)(*key_words)
        aeslib.AES256_CTR_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 8, ctypes.c_uint64]
        aeslib.AES256_CTR_encrypt.restypes = None
        aeslib.AES256_CTR_encrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

def AESdecrypt(version: str, input_filepath: str, output_filepath: str, key: int, nonce: int):

    if version not in ["128", "196", "256"]: raise ValueError("AES: Version must be in 128, 196, 256")
    aeslib = ctypes.CDLL(".\\aes.dll")

    if version == "128":
        key_words = [(key >> (32 * (3 - k))) & 0xFFFFFFFF for k in range(4)]
        key_words = (ctypes.c_uint32 * 4)(*key_words)
        aeslib.AES128_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 4, ctypes.c_uint64]
        aeslib.AES128_CTR_decrypt.restypes = None
        aeslib.AES128_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "196":
        key_words = [(key >> (32 * (5 - k))) & 0xFFFFFFFF for k in range(6)]
        key_words = (ctypes.c_uint32 * 6)(*key_words)
        aeslib.AES196_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 6, ctypes.c_uint64]
        aeslib.AES196_CTR_decrypt.restypes = None
        aeslib.AES196_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

    if version == "256":
        key_words = [(key >> (32 * (7 - k))) & 0xFFFFFFFF for k in range(8)]
        key_words = (ctypes.c_uint32 * 8)(*key_words)
        aeslib.AES256_CTR_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32 * 8, ctypes.c_uint64]
        aeslib.AES256_CTR_decrypt.restypes = None
        aeslib.AES256_CTR_decrypt(input_filepath.encode(), output_filepath.encode(), key_words, nonce)

class AES_ctx(ctypes.Structure):
    _fields_ = [
        ("key_schedule", ctypes.c_uint32 * 60),
        ("kLen", ctypes.c_size_t),
        ("nonctr", ctypes.c_uint32 * 4)
    ]

class AES:
    def __init__(self, key: bytes, key_length: int, nonce: int, _chunksize: int=2**19):

        self.key = key
        self.key_length = key_length
        self.nonce = nonce

        self._chunksize = _chunksize
        self.lib = ctypes.CDLL(r"C:\Users\danal\PycharmProjects\cryptography_project\primitives\aes.dll")

        self.cipher = self.lib.AES_CTR_encrypt_NEW
        self.cipher.argtypes = [ctypes.POINTER(AES_ctx), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        self.cipher.restype = None

        self.init = self.lib.AES_ctx_init
        self.init.argtypes = [ctypes.POINTER(AES_ctx), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64]
        self.init.restype = None

        self.ctx = AES_ctx()

        key_ctypes = (ctypes.c_uint8 * (key_length//8))(*key)

        self.init(self.ctx, key_ctypes, key_length, nonce)

    def encrypt_bytes(self, data: bytes) -> bytes:
        buffer = (ctypes.c_uint8 * len(data))(*data)
        self.cipher(ctypes.byref(self.ctx), buffer, len(data))
        return bytes(buffer)

    def encrypt_file(self, source: str, new_file: str) -> None:
        with open(source, 'rb') as sf, open(new_file, 'wb') as nf:
            buf = (ctypes.c_uint8 * self._chunksize)()
            while chunk := sf.read(self._chunksize):
                n = len(chunk)
                ctypes.memmove(buf, chunk, n)
                self.cipher(ctypes.byref(self.ctx), buf, n)
                nf.write(bytes(buf)[:n])
