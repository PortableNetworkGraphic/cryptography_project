#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
} RoundState;

__declspec(dllexport) uint32_t rotr32(uint32_t m, uint32_t n) {
    return m >> n | (m << (32-n));
}

__declspec(dllexport) uint64_t rotr64(uint64_t m, uint64_t n) {
    return m >> n | (m << (64-n));
}

__declspec(dllexport) RoundState round1(RoundState s,
    uint64_t Wi,
    uint64_t Ki,
    int vers
    ) {
        uint64_t CH = (s.e & s.f) ^ (~s.e & s.g);
        uint64_t S1;
        uint64_t S0;
        if(vers == 256) {
            S1 = rotr32(s.e, 6) ^ rotr32(s.e, 11) ^ rotr32(s.e, 25);
            S0 = rotr32(s.a, 2) ^ rotr32(s.a, 13) ^ rotr32(s.a, 22);
                    }
        else {
            S1 = rotr64(s.e, 14) ^ rotr64(s.e, 18) ^ rotr64(s.e, 41);
            S0 = rotr64(s.a, 28) ^ rotr64(s.a, 34) ^ rotr64(s.a, 39);
                    }
        uint64_t t1 = Wi + Ki + s.h + CH + S1;
        uint64_t t2 = ((s.a & s.b) ^ (s.a & s.c) ^ (s.b & s.c)) + S0;
        s.h = s.g;
        s.g = s.f;
        s.f = s.e;
        s.e = s.d + t1;
        s.d = s.c;
        s.c = s.b;
        s.b = s.a;
        s.a = t1 + t2;
        return s;

    }