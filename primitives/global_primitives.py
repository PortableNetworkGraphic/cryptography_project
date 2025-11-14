import math, random, sympy

def TEMPegcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = TEMPegcd(b % a, a)
        return g, x - (b // a) * y, y

def TEMPmodinv(a, m):
    g, x, y = extended_euclidean_algorithm(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    else:
        return x % m

def euclidean_algorithm(a: int, b: int) -> int:
    if a < 0 or b < 0: raise ValueError("Extended Euclidean Algorithm: Inputs must be non-negative")
    if a < b:
        a, b = b, a
    while b != 0:
        r = a % b
        a = b
        b = r
    return a

def extended_euclidean_algorithm(a: int, b: int) -> list[int]:
    if a < 0 or b < 0: raise ValueError("Extended Euclidean Algorithm: Inputs must be non-negative")
    swapped = False
    if not a >= b:
        swapped = True
        a, b = b, a
    if b == 0:
        d = a
        x = 1
        y = 0
        return [d,x,y]
    x2 = 1
    x1 = 0
    y2 = 0
    y1 = 1

    while b > 0:
        q = a//b
        r = a - q * b
        x = x2 - q * x1
        y = y2 - q * y1

        a = b
        b = r
        x2 = x1
        x1 = x
        y2 = y1
        y1 = y

    d = a
    x = x2
    y = y2
    return [d,x,y] if not swapped else [d,y,x]

def extended_euclidean_algorithm_x(a: int, b: int) -> int:
    y2 = 0
    y1 = 1

    while b > 0:
        q = a//b
        r = a - q * b
        y = y2 - q * y1

        a = b
        b = r

        y2 = y1
        y1 = y

    y = y2
    return y

def modular_multiplicative_inverse(a: int, p: int, q: int) -> int:

    # Calculates lambdaN knowing p and q
    lambdaN = ((p-1) * (q-1)) // euclidean_algorithm(p-1, q-1)

    # Uses lambda n to find the multiplicative inverse of the input a mod pq
    d = extended_euclidean_algorithm_x(lambdaN, a)

    # Account for f d is negative
    return d if d >= 0 else d + lambdaN