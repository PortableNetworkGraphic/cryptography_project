#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#define MAX_DIGITS 64

typedef struct {
	uint64_t words[MAX_DIGITS];
	size_t size;
} BigNum;

void print_big_num(BigNum num) {
	printf("0x");
	for (int i=num.size-1; i>=0; i--) {
		printf("%016llx", num.words[i]);
	}
	printf("\n");
}

bool greater_thanBN(BigNum a, BigNum b) {
	size_t size;
	if (a.size > b.size) {size = a.size;} else {size = b.size;}
	for (int i=size-1; i>=0; i--) {
		if (a.words[i] > b.words[i]) {
			return true;
		} else if (a.words[i] < b.words[i]) {
			return false;
		}
	}
	
	return false;
}

BigNum addBN(BigNum a, BigNum b) {
	BigNum r = {{}, a.size};
	if (a.size != b.size) {
		r.size = -1;
		return r;
	}
	uint64_t c = 0;
	for (int i=0; i<r.size; i++) {	
		r.words[i] = a.words[i] + b.words[i] + c;	
		c = (a.words[i]+b.words[i]+c) < a.words[i];	
	}
	return r;
}

int main() {
	
	BigNum n1 = {{7UL << 9, 15}, 3};
	BigNum n2 = {{16, 300000, 6}, 3};
	print_big_num(n1);
	print_big_num(n2);
	BigNum r0 = addBN(n1, n2);
	print_big_num(r0);
}