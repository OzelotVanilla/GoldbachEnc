from rsa.prime import getprime, are_relatively_prime, is_prime
from random import Random
from functools import reduce
from operator import mul


def isPrime(n: int) -> bool: return is_prime(n)


def isCoprime(a: int, b: int) -> bool: return are_relatively_prime(a, b)


def genPrime(*, n_bit: int = 64, exclude: list[int] = None) -> int:
    p = getprime(n_bit)

    if exclude is not None:
        while p in exclude:
            p = getprime(n_bit)

    return p


def getModInverse(of: int, under_mod: int, *,
                  get_random: bool = False,
                  bigger_than: int = None,
                  enlarge_range_left: int = -99,
                  enlarge_range_right: int = 99):
    result = pow(of, -1, under_mod)

    if get_random:
        # Bigger Than Mode
        if bigger_than is not None:
            while result <= bigger_than:
                result += Random().randint(under_mod, under_mod**4) * under_mod
        else:
            result += Random().randint(int(enlarge_range_left), int(enlarge_range_right)) * under_mod

    return result


def genKeys(*, a_bit: int = 16, b_bit: int = 16) -> tuple[int, int, int, int, int, int, int]:
    """
    n = a + b.
    """
    a, b, n = 0, 0, 0
    a_inv, b_inv = 0, 0
    while True:
        # Generate a, b, n
        a, b = genPrime(n_bit=a_bit), genPrime(n_bit=b_bit)
        n = a + b  # Goldbach here!
        n_a_b_not_coprime = not (isCoprime(a, n) and isCoprime(b, n))
        if n_a_b_not_coprime:
            continue

        break

    # Get enlarge factor `k`, this makes k harder to decode to `n`
    k = n * reduce(mul, [genPrime(n_bit=16, exclude=[n]) for _ in range(4)])

    # Find the a^-1 and b^-1 according to n
    a_inv = getModInverse(a, n, get_random=True, bigger_than=k)
    b_inv = getModInverse(b, n, get_random=True, bigger_than=k)
    # Make them big enough, so they can perform "mod k",
    #  and let the encrypted message not able to be calc (if m * a_inv < k, it is obvious to steal)
    return a, b, n, a_inv, b_inv, k
