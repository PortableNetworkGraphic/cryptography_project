class AES:


    SBOX = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
    ]

    def __init__(self, key: int, key_size: int=128):


        if key_size not in [128, 196, 256]:
            raise KeyError("Key must be size 128, 196 or 256, not "+str(key_size)+".")
        if key < 0:
            raise KeyError("Key too small.")
        elif key > (1<<key_size)-1:
            raise KeyError("Key too large. OwO")

        self.key = key
        self.key_size = key_size
        self.key_num: {}
        self.Nr = {128: 10, 196: 12, 256: 14}[key_size]
        self.Nk = {128: 4, 196: 6, 256: 8}[key_size]
        self.round_keys: list = self.KeyExpansion()

    def KeyExpansion(self) -> list[list]:
        w = [[-1, -1, -1, -1] for i in range(4*(self.Nr+1))]
        for i in range(self.Nk):
            w[i] = [(self.key >> (8 * (self.key_size // 8 - 1 - (4 * i + j)))) & 0xFF for j in range(4)]
        for i in range(self.Nk, 4*(self.Nr+1)):
            t: list[int] = w[i-1]
            if i % self.Nk == 0:
                t = [y^z for y, z in zip(AES.SubWord(AES.RotWord(t)), AES.Rcon(i//self.Nk))]
            elif self.key_size == 256 and i + 4 % 8 == 0:
                t = w[i] = AES.SubWord(t)
            w[i] = [x^y for x, y in zip(w[i-self.Nk], t)]

        return w

    @staticmethod
    def Rcon(j: int) -> list[int]:
        if not 1 <= j <= 10:
            raise ValueError("please!")
        return [AES.GFMod(2**(j-1)), 0, 0, 0]

    @staticmethod
    def RotWord(word: list[int]) -> list[int]:
        if len(word) != 4:
            raise IndexError("RotWord: Word is not 4 bytes")

        return [word[1], word[2], word[3], word[0]]

    @staticmethod
    def SubWord(word: list[int]) -> list[int]:
        if len(word) != 4:
            raise IndexError("SubWord: Word is not 4 bytes")

        return list(map(AES.SBox, word))


    @staticmethod
    def SBox(a: int) -> int:
        if not 0 <= a <= 0xFF:
            raise ValueError("SBox: Input integer out of range")

        x, y = (a >> 4) & 0xF, a & 0xF
        return AES.SBOX[x][y]

    # reduces some byte polynomial b(x) by mod m(x), where m(x) is the fixed reducing polynomial for the Rijndael field.
    @staticmethod
    def GFMod(a: int) -> int:
        while a.bit_length() >= 9:
            a = a ^ (0x11B << (a.bit_length() - 9))

        return a

    # calculates a(x) ^ q (mod m(x))
    @staticmethod
    def GFPow(a: int, q: int) -> int:

        r: int = 1

        while q != 0:
            if (q & 1) == 1:
                r = AES.GFMul(r, a)
            a = AES.GFMul(a, a)
            q >>= 1

        return r

    # calculates a(x) + b(x) (mod m(x))
    @staticmethod
    def GFAdd(a: int, b: int) -> int:
        return a ^ b

    # calculates a(x) * b(x) (mod m(x))
    @staticmethod
    def GFMul(a, b) -> int:

        p: int = 0

        while b != 0:
            if (b & 1) == 1:
                p ^= a
            a <<= 1
            b >>= 1

        return AES.GFMod(p)

    # finds some n such that na == 1 (mod m(x))
    @staticmethod
    def GFMulInv(a: int) -> int:
        return AES.GFPow(a, 254)

    @staticmethod
    def SubBytes(state: list[list[int]]) -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] = AES.SBox(c)

    @staticmethod
    def ShiftRows(state: list[list[int]]) -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] = state[r][(c+r) % 4]

    @staticmethod
    def MixColumns(state: list[list[int]]) -> None:
        for c in range(4):
            state[0][c] = (AES.GFMul(2, state[0][c])) ^ (AES.GFMul(3, state[0][c])) ^ (state[0][c]) ^ (state[0][c])
            state[1][c] = (state[0][c]) ^ (AES.GFMul(2, state[0][c])) ^ (AES.GFMul(3, state[0][c])) ^ (state[0][c])
            state[2][c] = (state[0][c]) ^ (state[0][c]) ^ (AES.GFMul(2, state[0][c])) ^ (AES.GFMul(3, state[0][c]))
            state[3][c] = (AES.GFMul(3, state[0][c])) ^ (state[0][c]) ^ (state[0][c]) ^ (AES.GFMul(2, state[0][c]))

    def AddRoundKey(self, state: list[list[int]], r: int) -> None:
        for c in range(4):
            state[0][c] ^= self.round_keys[4 * r + c]
            state[1][c] ^= self.round_keys[4 * r + c]
            state[2][c] ^= self.round_keys[4 * r + c]
            state[3][c] ^= self.round_keys[4 * r + c]