#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <gmp.h>

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

bool eqBN(BigNum a, BigNum b) {
	size_t size;
	if (a.size > b.size) {size = a.size;} else {size = b.size;}
	for (size_t i=size; i-- > 0; ) {
		if (a.words[i] != b.words[i]) {
			return false;
		}
	}
	
	return true;
}

bool eqzeroBN(BigNum a) {
	size_t size;
	BigNum b = {{}, a.size};
	return eqBN(a, b);
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
		c = (r.words[i] < a.words[i]) || ((b.words[i] + c) < b.words[i]); 	
	}
	return r;
}

BigNum subBN(BigNum a, BigNum b) {
	BigNum r = {{}, a.size};
	if (a.size != b.size) {
		r.size = -1;
		return r;
	}
	uint64_t c = 0;
	for (int i=0; i<r.size; i++) {
		r.words[i] = a.words[i] - b.words[i] - c;
		c = (r.words[i] > a.words[i]) || ((b.words[i] + c) < b.words[i]);
	}
	return r;
}

BigNum lshiftBN(BigNum a, size_t n) {
	if (!n) {return a;}
	
	BigNum r = a;
	
	for (int j=0; j<n; j++) {
		uint64_t tc = 0;
		uint64_t nc = 0;
		for (int i=0; i<r.size; i++) {	
			tc = r.words[i] >> 63;
			r.words[i] = (r.words[i] << 1) + (nc);
			nc = tc;
		}
	}
	
	return r;
}

BigNum rshiftBN(BigNum a, size_t n) {
	if (!n) {return a;}
	BigNum r = a;
	
	for (int j=0; j<n; j++) {
		uint64_t tc = 0;
		uint64_t nc = 0;
		for (size_t i = r.size; i-- > 0; ) {	
			tc = r.words[i] & (1);
			r.words[i] = (r.words[i] >> 1) + (nc << 63);
			nc = tc;
		}
	}
	
	return r;
}

BigNum mulBN(BigNum a, BigNum b) {
	BigNum r = {{}, a.size};
	if (a.size != b.size) {
		r.size = -1;
		return r;
	}
	BigNum t = b;
	BigNum eBN = {{}, t.size};
	
	int i = 0;
	while (!eqBN(t, eBN)) {
		if (t.words[0] & 1) {
			r = addBN(r, lshiftBN(a, i));
		}
		
		t = rshiftBN(t, 1);
		
		i++;
	}
	
	return r;
}

size_t MSBlenBN(BigNum x) {
	size_t len = 0;
	BigNum t = x;

	for (size_t i = t.size; i-- > 0; ) {
		if (t.words[i]) {
			len += i*64;
			uint64_t nt = t.words[i];
			while (nt) {
				len += 1;
				nt >>= 1;
			}
			
			return len;
		}
	}
	return len;
}

BigNum modBN(BigNum x, BigNum q) {
	BigNum t = x;
	
	while (greater_thanBN(t, q)) {
		size_t i = MSBlenBN(t)-MSBlenBN(q);
		BigNum s = lshiftBN(q, i);
		if (greater_thanBN(s, t)) {
			s = rshiftBN(s, 1);
		}
		
		t = subBN(t, s);
	}
	
	if (eqBN(t, q)) {
		t = subBN(t, q);
		return t;
	}
	
	return t;
}

BigNum powBN(BigNum x, BigNum e, BigNum q) {
	
	BigNum t = x;
	t.size = (size_t)(2*x.size);
	q.size = t.size;
	BigNum r = {{1}, t.size};
	
	BigNum eBN = {{0}, t.size};
	while (!eqBN(e, eBN)) {
		if (e.words[0] & 1) {
			r = mulBN(r, t);
			r = modBN(r, q);
		}
		t = mulBN(t, t);
		t = modBN(t, q);
		e = rshiftBN(e, 1);
	}
	
	q.size = x.size;
	r.size = x.size; 
	printf("%d\n", r.size);
	return r;
}



BigNum euclidean_algorithBN(BigNum a, BigNum b) {
	BigNum r;
	while (!eqzeroBN(b)) {
		r = modBN(a, b);
		a = b;
		b = r;
	}
	return a;
}

BigNum steinsBN(BigNum p, BigNum q) {
	
}

int main() {
	
	mpz_t a;
	mpz_init(a);
	mpz_set_ui(a, 12);
	
	mpz_t b;
	mpz_init(b);
	mpz_set_ui(b, 12);
	
	mpz_t t;
	mpz_init(t);
	
	mpz_add(t, a, b);
	gmp_printf("% Zd ", t);
}