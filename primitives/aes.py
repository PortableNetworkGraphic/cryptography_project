import ctypes


class AES_ctx(ctypes.Structure):
    _fields_ = [
        ("key_schedule", ctypes.c_uint32 * 60),
        ("kLen", ctypes.c_size_t),
        ("nonctr", ctypes.c_uint32 * 4)
    ]

class AES:
    def __init__(self, key: bytes, key_length: int, nonce: bytes, _chunksize: int=2**19):

        self.key = key
        self.key_length = key_length
        self.nonce = int.from_bytes(nonce)

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

        self.init(self.ctx, key_ctypes, key_length, self.nonce)

    def encrypt_bytes(self, data: bytes) -> tuple[bytes, int]:
        buffer = (ctypes.c_uint8 * len(data))(*data)
        self.cipher(ctypes.byref(self.ctx), buffer, len(data))
        return bytes(buffer), len(data)

    def encrypt_file(self, source: str, new_file: str) -> int:
        with open(source, 'rb') as sf, open(new_file, 'wb') as nf:
            buf = (ctypes.c_uint8 * self._chunksize)()
            nbytes = 0
            while chunk := sf.read(self._chunksize):
                n = len(chunk)
                nbytes += n
                ctypes.memmove(buf, chunk, n)
                self.cipher(ctypes.byref(self.ctx), buf, n)
                nf.write(bytes(buf)[:n])
            return nbytes
