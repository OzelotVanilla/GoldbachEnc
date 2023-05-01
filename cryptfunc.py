from str_manip import BitExtracter, StringBuffer, StringMakerFromBytes
from mathfunc import genKeys, getSafeRandomInt

from collections import deque
from collections.abc import MutableSequence
from enum import Enum


class PublicKey:
    def __init__(self, a_inv: int, b_inv: int, k: int, less_than_n_bit: int) -> None:
        self.a_inv = a_inv
        self.b_inv = b_inv
        self.k = k
        # This is used for stronger encrypt, tell the sender make chunk less than this bit.
        self.less_than_n_bit = less_than_n_bit

    def __str__(self) -> str:
        return f"Public@{{a_inv: {self.a_inv}, b_inv: {self.b_inv}, "\
            + f"k: {self.k}, less_than_n_bit: {self.less_than_n_bit}}}"


class PrivateKey:
    def __init__(self, a: int, b: int) -> None:
        self.a = a
        self.b = b
        self.n = a + b

    def __str__(self) -> str:
        return f"PrivateKey@{{a: {self.a}, b: {self.b}, n: {self.n}}}"


class GoldbachKey:
    def __init__(self, public_key: PublicKey, private_key: PrivateKey) -> None:
        self.public_key = public_key
        self.private_key = private_key


class GoldbachEncMessage:
    def __init__(self, message: MutableSequence[int], k: int) -> None:
        self.message = message
        self.k = k

    def __str__(self) -> str:
        return ""                                                                                 \
            + f"Encrypted message using GoldbachEnc with k = {self.k}.\n"                         \
            + f"\tMessage preview: {', '.join([str(self.message[i]) for i in range(5)])}.\n"


class EncDecMode(Enum):
    char_wise = 1
    byte_wise = 2


def generateKeyGoldbach():
    a, b, n, a_inv, b_inv, k = genKeys()

    # Give a random safe bit length
    n_bit_length = n.bit_length()
    # More than 10 bit will be safe ?
    # Also make sure that this length message, times `a_inv` or `b_inv`, will bigger than `k`
    # Maybe it can be reached by having a big `a_inv` and `b_inv` which is bigger than `k` ?
    less_than_n_bit = getSafeRandomInt(10, n_bit_length - 1)

    return GoldbachKey(PublicKey(a_inv, b_inv, k, less_than_n_bit), PrivateKey(a, b))


def encryptGoldbachSimple(message: str, a_inv: int, b_inv: int, k: int) -> tuple[list[int], int]:
    len_message = len(message)
    result = [0] * len_message

    for i in range(len_message):
        result[i] = ord(message[i]) * (a_inv if i % 2 == 0 else b_inv) % k

    return GoldbachEncMessage(result, k)


def decryptGoldbachSimple(message: list[int], a: int, b: int, n: int) -> str:
    len_message = len(message)
    result = [""] * len_message

    for i in range(len_message):
        result[i] = (message[i] % n * (a if i % 2 == 0 else b)) % n

    return "".join(map(lambda x: chr(int(x)), result))


def encryptGoldbach(message: str, public_key: PublicKey, *, encoding: str = "utf-8") -> deque[int]:
    # Use block cipher method to encode, block size is `less_than_n_bit`.
    i = 0
    a_inv = public_key.a_inv
    b_inv = public_key.b_inv
    k = public_key.k
    less_than_n_bit = public_key.less_than_n_bit

    extracter = BitExtracter(message)
    encrypt_result = deque(maxlen=int(extracter.getApproxSizeInBit() / less_than_n_bit) + 10)

    # While the string is not exhausted, can extract normally
    while extracter.isNotExhausted():
        # Since we add one more bit before the extract bit, so need to minus 1
        bits_extracted = extracter.getNBit(less_than_n_bit - 1, encoding=encoding)

        # If get a empty string
        if len(bits_extracted) == 0:
            break

        # Add leading one to the bit, to avoid the loss of leading zero when decrypting
        number_from_bits = BitExtracter.bitsToNumber([1] + bits_extracted)
        number_multiplied = number_from_bits * (a_inv if i % 2 == 0 else b_inv)

        # Checkpoint: If failed, it implies the a_inv or b_inv is still too small
        if number_multiplied < k:
            raise ArithmeticError(
                f"{'a_inv' if i % 2 == 0 else 'b_inv'} is too small ({(a_inv if i % 2 == 0 else b_inv)})! "
                + f"Should be greater than k ({k}), multiply result is {number_multiplied}"
            )

        encrypt_result.append(number_multiplied % k)
        i += 1

    # At now, either string exhausted (need add trailing zero), or end normally
    # Leave this question to decrypt, first send it through network
    return encrypt_result


def decryptGoldbach(message: deque[int], private_key: PrivateKey, *, encoding: str = "utf-8") -> str:
    a = private_key.a
    b = private_key.b
    n = private_key.n
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
    while len(message) > 0:
        x = message.popleft()

        # Decrypt the message
        x = x % n * (a if i % 2 == 0 else b) % n

        # Since the original bit for encrypt may contains leading zero,
        #  so this should add leading zero according to `less_than_n_bit`.
        # If it is the last number of the array,
        x_bits = BitExtracter.objToBits(x)

        # Delete the leading one, which is added in encryption phase
        x_bits = x_bits[1:]
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
