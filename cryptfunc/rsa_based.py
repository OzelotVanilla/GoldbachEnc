import sys
import os
sys.path.append(os.path.split(os.path.realpath(__file__))[0] + "/../cryptfunc")

from typelib import *

from mathfunc import *
from str_manip import *

# from sympy.ntheory import totient
from sympy.ntheory import reduced_totient as carmichael, totient as euler
from sympy import lcm as getLeastCommonMultiple
from functools import reduce
from operator import mul
from collections import deque

a, b, n, k, e, d = 0, 0, 0, 0, 0, 0


class PublicKey:
    def __init__(self, e: int, k: int, less_than_k_bit: int) -> None:
        self.e = e
        self.k = k
        # This is used for stronger encrypt, tell the sender make chunk less than this bit.
        self.less_than_k_bit = less_than_k_bit

    def __str__(self) -> str:
        return f"e: {self.e}, k: {self.k}, less_than_k_bit: {self.less_than_k_bit}"


class PrivateKey:
    def __init__(self, a: int, b: int, k: int, d: int) -> None:
        self.a = a
        self.b = b
        self.k = k
        self.d = d

    def __str__(self) -> str:
        return f"a: {self.a}, b: {self.b}, k: {self.k}, d: {self.d}"


def genKeys(*, a_bit: int = 16, b_bit: int = 16, n_factors_num: int = 4) -> tuple[int, int, int, int, int, int]:
    """
    n = a + b.
    """
    a, b, n = 0, 0, 0
    n_factors, two_prime, n_factors_mul, k = [], [], 0, 0

    while True:
        # Generate a, b, n
        a, b = genPrime(n_bit=a_bit), genPrime(n_bit=b_bit)
        n = a + b  # Goldbach here!
        if isNotPrime(n, exclude_factor=[2, 3, 7]):
            continue

        d = a * b
        if isNotCoprime(d, n):
            continue

        n_len = n.bit_length()
        # Get enlarge factor `k`, this makes k harder to decode to `n`
        n_factors = [genPrime(n_bit=getSafeRandomInt(4, n_len), coprime_with=[n, a, b]) for _ in range(n_factors_num)]
        two_prime = [genPrime(n_bit=getSafeRandomInt(n_len, n_len + 2), coprime_with=[n, a, b]) for _ in range(2)]
        prime_factors = n_factors  # + two_prime
        n_factors_mul = reduce(mul, prime_factors)
        k = n * n_factors_mul

        # The common factor of `p_i` must be very small. If possible, we say it less than 10.
        len_prime_factor = len(prime_factors)
        should_regenerate = False
        for i in range(len_prime_factor):
            if should_regenerate:
                break
            for j in range(i + 1, len_prime_factor):
                if gcd(prime_factors[i], prime_factors[j]) >= 10:
                    should_regenerate = True
                    break
        if should_regenerate:
            continue

        # Find lambda(k) (Carmichael totient function), as `k = n * p_1 * p_2 * ... * p_n`
        # lambda_pi = reduce(getLeastCommonMultiple, [i - 1 for i in prime_factors])
        # lambda_k = int(getLeastCommonMultiple(carmichael(n), lambda_pi))

        # Find phi(k) (euler totient function), as `k = n * p_1 * p_2 * ... * p_n`
        phi_k = int(euler(n)) * reduce(mul, [i - 1 for i in prime_factors])

        if d >= phi_k or d <= 0:
            continue

        if isNotCoprime(d, phi_k):
            continue

        break

    # Find `e` and `d` such that `m ** (e * d) % k = m`
    e = getModInverse(d, phi_k)

    # Make them big enough, so they can perform "mod k",
    #  and let the encrypted message not able to be calc (if m * a_inv < k, it is obvious to steal)
    return a, b, n, k, e, d


def generateKeyGoldbach(*, a_bit: int = 16, b_bit: int = 16, n_factors_num: int = 4) -> GoldbachKey:
    global a, b, n, k, e, d
    a, b, n, k, e, d = genKeys(a_bit=a_bit, b_bit=b_bit, n_factors_num=n_factors_num)

    # Give a random safe bit length
    k_bit_length = k.bit_length()
    # More than 10 bit will be safe ?
    # Also make sure that this length message, times `a_inv` or `b_inv`, will bigger than `k`
    # Maybe it can be reached by having a big `a_inv` and `b_inv` which is bigger than `k` ?
    less_than_k_bit = getSafeRandomInt(10, k_bit_length - 2)

    return GoldbachKey(PublicKey(e, k, less_than_k_bit), PrivateKey(a, b, k, d))


def encryptGoldbach(message: str, public_key: PublicKey, *, encoding: str = "utf-8") -> deque[int]:
    # Use block cipher method to encode, block size is `less_than_k_bit`.
    i = 0
    e = public_key.e
    k = public_key.k
    less_than_k_bit = public_key.less_than_k_bit

    extracter = BitExtracter(message)
    encrypt_result = deque(maxlen=int(extracter.getApproxSizeInBit() / less_than_k_bit) + 10)

    # While the string is not exhausted, can extract normally
    print("Encryption:")
    while extracter.isNotExhausted():
        # Since we add one more bit before the extract bit, so need to minus 1
        bits_extracted = extracter.getNBit(less_than_k_bit - 1, encoding=encoding)

        # If get a empty string
        if len(bits_extracted) == 0:
            break

        # Add leading one to the bit, to avoid the loss of leading zero when decrypting
        number_from_bits = BitExtracter.bitsToNumber([1] + bits_extracted + [1])
        print(f"i: {i},\t num_from_bit: {number_from_bits},\t coprime_num_n: {isCoprime(number_from_bits, n)}")
        number_result = pow(number_from_bits, e, k)

        encrypt_result.append(number_result)
        i += 1

    # At now, either string exhausted (need add trailing zero), or end normally
    # Leave this question to decrypt, first send it through network
    return encrypt_result


def decryptGoldbach(message: deque[int], private_key: PrivateKey, *, encoding: str = "utf-8") -> str:
    k = private_key.k
    d = private_key.d
    i = 0

    extracter = StringMakerFromBytes(encoding=encoding)

    # In order to avoid the resize of the deque.
    guess_bit_length_element = message[0].bit_length() + 5
    bits_buffer = deque(maxlen=guess_bit_length_element)

    # Guess the byte size of string and init the StringBuffer,
    #  give some compensate to the guess length
    guess_byte_num = (len(message) + 10) * guess_bit_length_element / 8
    decrypt_result = StringBuffer(allocate_n_byte=int(guess_byte_num))
    del guess_bit_length_element, guess_byte_num

    # Change the int to bytes, then convert to string and store it
    print("Decryption:")
    while len(message) > 0:
        x = message.popleft()

        # Decrypt the message
        x = pow(x, d, k)

        # Since the original bit for encrypt may contains leading zero,
        #  so this should add leading zero according to `less_than_n_bit`.
        # If it is the last number of the array,
        x_bits = BitExtracter.objToBits(x)

        # Delete the leading one, which is added in encryption phase
        x_bits = x_bits[1:-1]
        print(f"i: {i},\t num_from_bit: {x},\t coprime_num_n: {isCoprime(x, n)}")
        for bit in x_bits:
            bits_buffer.append(bit)

        # Every eight bit will be a byte (for string)
        while len(bits_buffer) >= 8:
            one_byte = BitExtracter.bitsToNumber([bits_buffer.popleft() for _ in range(8)])
            extracter.appendInt(one_byte)

        # Try to decode and extract
        extracter.decode()
        decrypt_result.write(extracter.extract())

        i += 1

    return decrypt_result.getvalue()
