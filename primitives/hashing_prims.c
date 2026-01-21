#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

typedef struct {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;
} SHA256_hash_state;

typedef struct {
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
} SHA512_hash_state;

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
		
uint32_t rotr32(uint32_t x, int n) {
	return (x >> n | (x << (32-n)));
}

uint64_t rotr64(uint64_t x, int n) {
	return (x >> n | (x << (64-n)));
}

void update_hash_state256(SHA256_hash_state *state, const uint8_t *data) {
	uint32_t w[64];
	
	uint32_t a = state->a;
	uint32_t b = state->b;
	uint32_t c = state->c;
	uint32_t d = state->d;
	
	uint32_t e = state->e;
	uint32_t f = state->f;
	uint32_t g = state->g;
	uint32_t h = state->h;

	for(int i=0; i<16; i++) {
		w[i] = 
			(data[4*i] << 24) |
			(data[4*i+1] << 16) |
			(data[4*i+2] << 8) |
			(data[4*i+3]);
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
	
	state->a += a;
	state->b += b;
	state->c += c;
	state->d += d;
	
	state->e += e;
	state->f += f;
	state->g += g;
	state->h += h;
		
} 

void update_hash_state512(SHA512_hash_state *state, const uint8_t *data) {
	uint64_t w[80];
	
	uint64_t a = state->a;
	uint64_t b = state->b;
	uint64_t c = state->c;
	uint64_t d = state->d;
	
	uint64_t e = state->e;
	uint64_t f = state->f;
	uint64_t g = state->g;
	uint64_t h = state->h;

	for(int i=0; i<16; i++) {
		w[i] = 
			((uint64_t)(data[8*i]) << 56) |
			((uint64_t)(data[8*i+1]) << 48) |
			((uint64_t)(data[8*i+2]) << 40) |
			((uint64_t)(data[8*i+3]) << 32) |
			((uint64_t)(data[8*i+4]) << 24) |
			((uint64_t)(data[8*i+5]) << 16) |
			((uint64_t)(data[8*i+6]) << 8) |
			((uint64_t)(data[8*i+7]));
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
	
	state->a += a;
	state->b += b;
	state->c += c;
	state->d += d;
	
	state->e += e;
	state->f += f;
	state->g += g;
	state->h += h;
		
} 

__declspec(dllexport) void SHA256bp(SHA256_hash_state hs, const char *input_path) {
	uint8_t buffer[64];
	FILE *stream;
	stream = fopen(input_path, "rb");
	unsigned int count;
	uint64_t mLen = 0;
	bool further_padding = false;
	uint32_t w[64] = {0};

	do {
		count = fread(buffer, 1, 64, stream);
		mLen = mLen + 8 * count;
		
		if((56 < count) && (count < 64)) {
			further_padding = true;
			buffer[count] = 0x80;
			for(int i=count+1; i<56; i++) {
				buffer[i] = 0x00;
			}
		} else if(count <= 56) {
			buffer[count] = 0x80;
			for(int i=count+1; i<56; i++) {
				buffer[i] = 0x00;
			}		

			for(int i=0; i<8; i++) {				
				buffer[i+56] = (uint8_t)((mLen >> (8*(7-i))) & 0xFF);
			}
		}
				
		update_hash_state256(&hs, buffer);
		
	} while(count == 64);
	
	fclose(stream);
}

__declspec(dllexport) void SHA512bp(SHA512_hash_state hs, const char *input_path) {
	uint8_t buffer[128];
	FILE *stream;
	stream = fopen(input_path, "rb");
	unsigned int count;
	uint64_t len_hi = 0;
	uint64_t len_lo = 0;
	bool further_padding = false;
	uint64_t w[80] = {0};

	do {
		count = fread(buffer, 1, 128, stream);
		uint64_t add = (uint64_t)count * 8ULL;
		uint64_t old_lo = len_lo;
		len_lo += add;
		if (len_lo < old_lo) ++len_hi;

		
		if((112 < count) && (count < 128)) {
			buffer[count] = 0x80;
			further_padding = true;
			for(int i=count+1; i<128; i++) {
				buffer[i] = 0x00;
			}
		} else if(count <= 112) {
			if(!further_padding) {
				buffer[count] = 0x80;
			}
			for(int i=count+1; i<112; i++) {
				buffer[i] = 0x00;
			}		

			for (int i = 0; i < 8; ++i) {
				buffer[112 + i] = (uint8_t)((len_hi >> (56 - 8*i)) & 0xFF);
			}
			for (int i = 0; i < 8; ++i) {
				buffer[120 + i] = (uint8_t)((len_lo >> (56 - 8*i)) & 0xFF);
}
		}
		
		update_hash_state512(&hs, buffer);
		
	} while(count == 128);
			
	
	fclose(stream);
}
