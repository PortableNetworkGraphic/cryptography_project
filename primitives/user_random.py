from time import sleep, time_ns
import pyautogui

"""
IMPORTANT
This primative is not complete, and implements a 'toy' hashing function for testing purposes.
"""


def toy_hash(x: int) -> int:
    return pow(x, 2**128-36656, 2**128+1)

def get_rand_bits(n: int) -> int:

    digest = 0x0
    for i in range(2*n):
        sleep(1/(2*n))
        digest = digest << 64 | pyautogui.position()[0]
        digest = digest << 64 | pyautogui.position()[1]
        digest = digest << 64 | time_ns()
        digest = digest << 16 | i
        digest = toy_hash(digest) >> 17
    return digest