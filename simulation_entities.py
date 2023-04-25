from random import Random
from mathfunc import genKeys
from cryptfunc import *


class PublicKey:
    def __init__(self, a_inv: int, b_inv: int, k: int, less_than_n_bit: int) -> None:
        self.a_inv = a_inv
        self.b_inv = b_inv
        self.k = k
        # This is used for stronger encrypt, tell the sender make chunk less than this bit.
        self.less_than_n_bit = less_than_n_bit


class PrivateKey:
    def __init__(self, a: int, b: int) -> None:
        self.a = a
        self.b = b
        self.n = a + b


class GoldbachKey:
    def __init__(self, public_key: PublicKey, private_key: PrivateKey) -> None:
        self.public_key = public_key
        self.private_key = private_key


class User:
    ...


class User:
    def generateKey(self): ...

    def passPublicKeyTo(self, user: User): ...

    def savePublicKey(self, name: str, key: int): ...

    def sendEncMsgTo(self, name: str, message: str): ...


class User:
    def __init__(self, name: str) -> None:
        self.name = name
        # This map key_name to `k` value
        self.key_name_map: dict[str, int] = dict()
        # This is multiple instances of my key, queried by `k` value
        self.key_holder: dict[int, GoldbachKey] = dict()
        # This is others' key
        self.key_of_others: dict[str, PublicKey] = dict()

    def generateKey(self, *, key_name: str = None):
        a, b, n, a_inv, b_inv, k = genKeys()

        # Give a random safe bit length
        n_bit_length = n.bit_length()
        # More than 10 bit will be safe ?
        # Also make sure that this length message, times `a_inv` or `b_inv`, will bigger than `k`
        # Maybe it can be reached by having a big `a_inv` and `b_inv` which is bigger than `k` ?
        less_than_n_bit = Random().randint(10, n_bit_length - 1)

        if key_name is not None:
            self.key_name_map[key_name] = k

        self.key_holder[k] = GoldbachKey(PublicKey(a_inv, b_inv, k, less_than_n_bit), PrivateKey(a, b))

    def sendPublicKeyTo(self, user: User, *, use_key_with_name: str = None):
        if len(self.key_holder) == 0:
            self.generateKey()

        # If specifying the key name
        if use_key_with_name is not None:
            if use_key_with_name not in self.key_name_map:
                raise KeyError(f"Key \"{use_key_with_name}\" not in user \"{self.name}\"'s named key.")
            public_key = self.key_holder[self.key_name_map[use_key_with_name]]
        # If not specifying the key name, use default
        else:
            # The key used is not named
            unnamed_keys = [k for k in self.key_holder if k not in self.key_name_map.values()]
            public_key = self.key_holder[unnamed_keys[Random().randint(0, len(unnamed_keys) - 1)]].public_key

        user.savePublicKey(self.name, public_key)

    def savePublicKey(self, name: str, key: PublicKey):
        self.key_of_others[name] = key

    def sendEncMsgTo(self, name: str, message: str) -> tuple[list[int], int]:
        if name not in self.key_of_others:
            raise KeyError(f"The user \"{self.name}\" does not have user \"{name}\" public key.")

        keys = self.key_of_others[name]
        return encryptGoldbachSimple(message, keys.a_inv, keys.b_inv, keys.k)

    def decryptEncMsg(self, enc_message: tuple[list[int], int]) -> str:
        message, k = enc_message
        keys = self.key_holder[k].private_key

        return decryptGoldbachSimple(message, keys.a, keys.b, keys.n)
