def extended_euclidean_algorithm(a: int, b: int) -> [int, int, int]:
    if a < 0 or b < 0: raise ValueError("Extended Euclidean Algorithm: Inputs must be non-negative")
    swapped = False
    if not a >= b:
        swapped = True
        a, b = b, a
    if b == 0:
        d = a
        x = 1
        y = 0
        return d,x,y
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
    return d,x,y if not swapped else d,y,x

print(extended_euclidean_algorithm(4864, 3458))

def eea_x(a: int, b: int) -> int:
    if a < 0 or b < 0: raise ValueError("Extended Euclidean Algorithm: Inputs must be non-negative")
    if not a >= b: raise ValueError("First input must suceed second.")
    if b == 0:
        x = 1
        return x
    x2 = 1
    x1 = 0

    while b > 0:
        q = a//b
        r = a - q * b
        x = x2 - q * x1

        a = b
        b = r
        x2 = x1
        x1 = x

    x = x2
    return x

print(eea_x(4864, 3458))

def modular_mult(): pass