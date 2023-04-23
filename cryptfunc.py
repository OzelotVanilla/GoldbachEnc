from random import Random
from functools import reduce
from operator import mul


def encryptGoldbachSimple(message: str, a_inv: int, b_inv: int, k: int) -> tuple[list[int], int]:
    len_message = len(message)
    result = [0] * len_message

    for i in range(len_message):
        result[i] = ord(message[i]) * (a_inv if i % 2 == 0 else b_inv) % k

    return (result, k)


def decryptGoldbachSimple(message: list[int], a: int, b: int, n: int) -> str:
    len_message = len(message)
    result = [""] * len_message

    for i in range(len_message):
        result[i] = (message[i] % n * (a if i % 2 == 0 else b)) % n

    return "".join(map(lambda x: chr(int(x)), result))


# TODO This should make a stronger encypt method
def encryptGoldbach(message: str, a_inv: int, b_inv: int, k: int) -> list[int]:
    message_bytes = message.encode()
    print(message_bytes)


# TODO
def decryptGoldbach(message: list[int], a, b, n, x) -> str:
    pass


if __name__ == "__main__":
    encryptGoldbach("Test", 1, 1, 1)
