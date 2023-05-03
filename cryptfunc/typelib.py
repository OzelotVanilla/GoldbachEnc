from collections.abc import MutableSequence
from enum import Enum


class PublicKey:
    # Should explicitly defined in each module.
    ...


class PrivateKey:
    # Should explicitly defined in each module.
    ...


class GoldbachKey:
    def __init__(self, public_key: PublicKey, private_key: PrivateKey) -> None:
        self.public_key = public_key
        self.private_key = private_key

    def __str__(self) -> str:
        return f"\tPublic: {self.public_key}\n\tPrivate: {self.private_key}"


class GoldbachEncMessage:
    def __init__(self, message: MutableSequence[int], identifier: int) -> None:
        self.message = message
        self.identifier = identifier

    def __str__(self) -> str:
        return ""                                                                                 \
            + f"Encrypted message using GoldbachEnc with k = {self.k}.\n"                         \
            + f"\tMessage preview: {', '.join([str(self.message[i]) for i in range(5)])}.\n"


class EncDecMode(Enum):
    char_wise = 1
    byte_wise = 2
