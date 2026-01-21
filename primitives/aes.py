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
