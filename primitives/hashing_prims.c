#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

static const uint32_t SHA256_round_constants[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
static const uint64_t SHA512_round_constants[80] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

typedef struct {
	uint32_t h[8];
} Hashstate32;

typedef struct {
	uint64_t h[8];
} Hashstate64;

uint32_t rotr32(uint32_t x, int n) {
	return (x >> n | (x << (32-n)));
}

uint64_t rotr64(uint64_t x, int n) {
	return (x >> n | (x << (64-n)));
}

//                                        Hash State   , nchunk, chunk bytes
__declspec(dllexport) Hashstate32 SHA256(Hashstate32 hs, int nc, unsigned char *cbytes) {
	
	// 2d array where the row is the iteration of the hash input, and
	// the column is the word for the input.
	uint32_t w[64] = {0};
	for(int i=0; i<nc; i++) {
		// because of the way SHA256 works, only 16 of the 64 round
		// words are generated here.
		for(int j=0; j<16; j++){
			int offset = i*64+j*4;
			w[j] = 
				((uint32_t)cbytes[offset] << 24) |
				((uint32_t)cbytes[offset + 1] << 16) |
				((uint32_t)cbytes[offset + 2] << 8) |
				((uint32_t)cbytes[offset + 3]);
			if (offset + 3 >= nc * 64) {
				printf("Out of bounds read at %d\n", offset);
				break;
				}
		}
		
		for(int j=16; j<64; j++) {
			uint32_t x = w[j-2];
			uint32_t y = w[j-15];
			
			w[j] = 
				(rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)) +
				w[j-7] +
				(rotr32(y, 7) ^ rotr32(y, 18) ^ (y >> 3)) +
				w[j-16];
		}
		
		uint32_t a = hs.h[0];
		uint32_t b = hs.h[1];
		uint32_t c = hs.h[2];
		uint32_t d = hs.h[3];
		
		uint32_t e = hs.h[4];
		uint32_t f = hs.h[5];
		uint32_t g = hs.h[6];
		uint32_t h = hs.h[7];
		
		for(int j=0; j<64; j++) {
			
			uint32_t ch = (e & f) ^ (~e & g);
			uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
			uint32_t t1 = w[j] + SHA256_round_constants[j] + h + ch + s1;
			uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
			
			uint32_t t2 = (((a & b) ^ (a & c) ^ (b & c)) + s0);
			h = g;
			g = f;
			f = e;
			e = t1 + d;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		hs.h[0] += a;
		hs.h[1] += b;
		hs.h[2] += c;
		hs.h[3] += d;
		
		hs.h[4] += e;
		hs.h[5] += f;
		hs.h[6] += g;
		hs.h[7] += h;
		
	}
	return hs;
}

//                                        Hash State   , nchunk, chunk bytes
__declspec(dllexport) Hashstate64 SHA512(Hashstate64 hs, int nc, unsigned char *cbytes) {
	
	// 2d array where the row is the iteration of the hash input, and
	// the column is the word for the input.
	uint64_t w[80] = {0};
	for(int i=0; i<nc; i++) {
		// because of the way SHA256 works, only 16 of the 64 round
		// words are generated here.
		for(int j=0; j<16; j++){
			int offset = i*128+j*8;
			w[j] = 
				((uint64_t)cbytes[offset] << 56) |
				((uint64_t)cbytes[offset + 1] << 48) |
				((uint64_t)cbytes[offset + 2] << 40) |
				((uint64_t)cbytes[offset + 3] << 32) |
				((uint64_t)cbytes[offset + 4] << 24) |
				((uint64_t)cbytes[offset + 5] << 16) |
				((uint64_t)cbytes[offset + 6] << 8) |
				((uint64_t)cbytes[offset + 7]);
			if (offset + 7 >= nc * 128) {
				printf("Out of bounds read at %d\n", offset);
				break;
				}
		}
		
		for(int j=16; j<80; j++) {
			uint64_t x = w[j-2];
			uint64_t y = w[j-15];
			
			w[j] = 
				(rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)) +
				w[j-7] +
				(rotr64(y, 1) ^ rotr64(y, 8) ^ (y >> 7)) +
				w[j-16];
		}
		
		uint64_t a = hs.h[0];
		uint64_t b = hs.h[1];
		uint64_t c = hs.h[2];
		uint64_t d = hs.h[3];
		
		uint64_t e = hs.h[4];
		uint64_t f = hs.h[5];
		uint64_t g = hs.h[6];
		uint64_t h = hs.h[7];
		
		for(int j=0; j<80; j++) {
			
			uint64_t ch = (e & f) ^ (~e & g);
			uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
			uint64_t t1 = w[j] + SHA512_round_constants[j] + h + ch + s1;
			uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
			
			uint64_t t2 = (((a & b) ^ (a & c) ^ (b & c)) + s0);
			h = g;
			g = f;
			f = e;
			e = t1 + d;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		hs.h[0] += a;
		hs.h[1] += b;
		hs.h[2] += c;
		hs.h[3] += d;
		
		hs.h[4] += e;
		hs.h[5] += f;
		hs.h[6] += g;
		hs.h[7] += h;
		
	}
	return hs;
}