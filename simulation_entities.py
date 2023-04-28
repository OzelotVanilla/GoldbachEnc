from random import Random
from cryptfunc import *


class User:
    ...


class User:
    def generateKey(self): ...

    def passPublicKeyTo(self, user: User): ...

    def savePublicKey(self, name: str, key: int): ...

    def sendEncMsgTo(self, name: str, message: str): ...

    def decryptEncMsg(self, enc_message: tuple[list[int], int]) -> str: ...


class User:
    def __init__(self, name: str) -> None:
        self.name = name
        # This map key_name to `k` value
        self.key_name_map: dict[str, int] = dict()
        # This is multiple instances of my key, queried by `k` value
        self.key_holder: dict[int, GoldbachKey] = dict()
        # This is others' key
        self.key_of_others: dict[str, PublicKey] = dict()

        # Set the default encode and decode method
        self.encode_method = self.decode_method = "utf-8"

    def generateKey(self, *, key_name: str = None):
        goldbach_key = generateKeyGoldbach()
        k = goldbach_key.public_key.k

        if key_name is not None:
            self.key_name_map[key_name] = k

        self.key_holder[k] = goldbach_key

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

    def sendEncMsgTo(self, name: str, message: str, mode: EncDecMode = EncDecMode.byte_wise) -> tuple[list[int], int]:
        if name not in self.key_of_others:
            raise KeyError(f"The user \"{self.name}\" does not have user \"{name}\" public key.")

        keys = self.key_of_others[name]
        match mode:
            case EncDecMode.byte_wise:
                return GoldbachEncMessage(encryptGoldbach(message, keys), keys.k)
            case EncDecMode.char_wise:
                return GoldbachEncMessage(encryptGoldbachSimple(message, keys.a_inv, keys.b_inv, keys.k))

    def decryptEncMsg(self, enc_message: GoldbachEncMessage, mode: EncDecMode = EncDecMode.byte_wise) -> str:
        message, k = enc_message.message, enc_message.k
        keys = self.key_holder[k].private_key
        match mode:
            case EncDecMode.byte_wise:
                return decryptGoldbach(message, keys)
            case EncDecMode.char_wise:
                return decryptGoldbachSimple(message, keys.a, keys.b, keys.n)
