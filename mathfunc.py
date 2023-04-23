from rsa.prime import getprime, are_relatively_prime, is_prime
from random import Random
from functools import reduce
from operator import mul
from math import sqrt


def isPrime(n: int) -> bool: return is_prime(n)


def isCoprime(a: int, b: int) -> bool: return are_relatively_prime(a, b)


def genPrime(*, n_bit: int = 64) -> int: return getprime(n_bit)


def getModInverse(of: int, under_mod: int, *,
                  get_random: bool = False,
                  enlarge_range_left: int = -99,
                  enlarge_range_right: int = 99):
    if get_random:
        return pow(of, -1, under_mod) + \
            Random().randint(int(enlarge_range_left), int(enlarge_range_right)) * under_mod
    else:
        return pow(of, -1, under_mod)


def genKeys(*, a_bit: int = 16, b_bit: int = 16) -> tuple[int, int, int, int, int, int, int]:
    """
    n = a + b.
    """
    a, b, n = 0, 0, 0
    a_inv, b_inv = 0, 0
    need_regenerate = True
    while need_regenerate:
        # Generate a, b, n
        a, b = genPrime(n_bit=a_bit), genPrime(n_bit=b_bit)
        n = a + b  # Goldbach here!
        n_a_b_not_coprime = not (isCoprime(a, n) and isCoprime(b, n))
        if n_a_b_not_coprime:
            continue

        # Generate x, which will be exchange secretly
        x = Random().randint(-2**16, 2**16)
        n_x_not_coprime = not isCoprime(n, x)
        if n_x_not_coprime:
            continue

        need_regenerate = False

    # Get enlarge factor `k`, this makes k harder to decode to `n`
    k = n * reduce(mul, [genPrime(n_bit=16) for _ in range(4)])

    # Find the a^-1 and b^-1 according to n
    a_inv = getModInverse(a, n, get_random=True, enlarge_range_left=sqrt(k), enlarge_range_right=k)
    b_inv = getModInverse(b, n, get_random=True, enlarge_range_left=sqrt(k), enlarge_range_right=k)
    # Make them big enough, so they can perform "mod k",
    #  and let the encrypted message not able to be calc (if m * a_inv < k, it is obvious to steal)
    return a, b, n, a_inv, b_inv, x, k


if __name__ == "__main__":
    print(genKeys())
