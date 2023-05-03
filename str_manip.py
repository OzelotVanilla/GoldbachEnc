from functools import reduce
from operator import add
from collections import deque
from io import StringIO
from sys import getsizeof

import math
import os

__all__ = ["BitExtracter", "StringBuffer", "StringMakerFromBytes"]


class BitExtracter:
    def __init__(self, of: object) -> None:
        self.__origin = str(of)
        self.__position_by_codepoint = 0
        self.__position_in_bit = 0
        self.__getNBit_buffer_of_remain: deque[int] = deque()
        self.__origin_str_exhausted = False

    def getNBit(self, n_bit: int, *, encoding: str = "utf-8") -> list[int]:
        """
        Extract n bits from the string, and return to you.

        NOTICE: if you just exhausted the string, the result will have trailing zero.
        You should always check whether the string is exhausted.
        """
        # If the string is already exhausted, should not start
        if self.__origin_str_exhausted:
            raise EOFError(f"The string you want to extract is already exhausted.")

        n_bit_to_extract = n_bit
        result = [0] * n_bit_to_extract
        result_write_position = 0

        # If there is remained bits in the buffer, use them
        len_remaining_bits = len(self.__getNBit_buffer_of_remain)
        if len_remaining_bits > 0:
            can_append_n_bit = min(n_bit_to_extract, len_remaining_bits)
            while result_write_position < can_append_n_bit:
                result[result_write_position] = self.__getNBit_buffer_of_remain.popleft()
                result_write_position += 1

            n_bit_to_extract -= can_append_n_bit

        # Extract new bytes from string if still need to append
        if n_bit_to_extract > 0:
            guess_num_of_char_extract = math.ceil(n_bit_to_extract / 8)
            extracted_byte = self.__getNCharFromOrigin(guess_num_of_char_extract).encode(encoding)

            # If the extracter is already exhausted here, it will get empty string
            if len(extracted_byte) == 0:
                self.__origin_str_exhausted = True
                return result[0:result_write_position]

            # Concat lists of bits
            bits_array = reduce(add, [BitExtracter.objToBits(c, in_byte_width=True) for c in extracted_byte])
            bits_array_len = len(bits_array)

            # Checkpoint: `bits_array` must be longer than `n_bit_to_extract`
            # If not enough length, means you have exhausted the string
            if bits_array_len < n_bit_to_extract:
                # raise BufferError(f"Requiring {n_bit} bits, but got {bits_array_len} len buffer with {bits_array}.")
                self.__origin_str_exhausted = True
                n_bit_to_extract = bits_array_len

            # Extract the number that is needed
            bits_array_read_position = 0
            while bits_array_read_position < n_bit_to_extract:
                result[result_write_position] = bits_array[bits_array_read_position]
                bits_array_read_position += 1
                result_write_position += 1

            # Eliminate zeros that is not belongs to the result (since result array is filled with 0 when init)
            result = result[0:result_write_position]

            # Push the remained elements to the buffer, if any
            for i in range(bits_array_read_position, bits_array_len):
                self.__getNBit_buffer_of_remain.append(bits_array[i])

        self.__position_in_bit += len(result)

        return result

    def objToBits(of: bytes | int, *, in_byte_width: bool = False) -> list[int]:
        """
        `in_byte_width` will make the output bits length equals to times of 8.
        Like 71 will be [0, 1, 0, 0, 0, 1, 1, 1] if this option is turned on.
        """
        match of:
            case bytes():
                result = [0] * len(of) * 8
                i = 0
                for byte in of:
                    for at_bit in range(8):
                        result[i] = (byte >> (7 - at_bit)) & 1
                        i += 1

                return result

            case int():
                # Like 71 is [1, 0, 0, 0, 1, 1, 1], 7 bit length,
                #  the first bit need to bring down only 6 times to reach 1's place.
                start_at = of.bit_length() - 1
                result = [(of >> weight) & 1 for weight in range(start_at, -1, -1)]

                if in_byte_width:
                    len_result = len(result)
                    num_of_zero_to_append = 8 - len_result % 8
                    result = [0] * num_of_zero_to_append + result

                return result

            case _:
                raise TypeError(f"Unsupported type {type(of)} for `bytesToBits`.")

    def bitsToNumber(of_bits_arr: list[int]) -> int:
        result = 0
        arr_length = len(of_bits_arr)

        for i in range(arr_length):
            if of_bits_arr[i] > 0:
                result += 1 << (arr_length - 1 - i)

        return result

    def isExhausted(self) -> bool:
        return self.__origin_str_exhausted

    def isNotExhausted(self) -> bool:
        return not self.__origin_str_exhausted

    def getApproxSizeInByte(self) -> int:
        # The size may be not accurate, only for your reference
        return getsizeof(self.__origin) - getsizeof("")

    def getApproxSizeInBit(self) -> int:
        return self.getApproxSizeInByte() * 8

    def getPositionInBit(self) -> int:
        return self.__position_in_bit

    def getPositionInByte(self) -> int:
        return self.getPositionInBit() / 8

    def __getNCharFromOrigin(self, n_char: int) -> str:
        possible_max_position_exclude = min(self.__position_by_codepoint + n_char, len(self.__origin))
        result = self.__origin[self.__position_by_codepoint:possible_max_position_exclude]
        self.__position_by_codepoint = possible_max_position_exclude
        if len(result) == 0:
            self.__origin_str_exhausted = True
        return result


class StringBuffer(StringIO):
    ...


class StringBuffer(StringIO):
    def __init__(self, initial_value: str | None = None, *,
                 allocate_n_byte: int = None,
                 newline: str | None = "\n") -> None:
        super().__init__(initial_value, newline)

        if allocate_n_byte is not None:
            self.resize(allocate_n_byte)

    def appendAsString(self, obj: str | bytes) -> StringBuffer:
        match obj:
            case str():
                self.write(obj)

            case bytes():
                self.write(obj.decode())

            case _:
                raise TypeError(f"Unsupported type {type(obj)}.")

        return self

    def toString(self) -> str:
        return self.getvalue()

    def getSizeInBit(self) -> int:
        origin_ptr_pos = self.tell()
        self.seek(0, os.SEEK_END)
        size_self = self.tell()
        self.seek(origin_ptr_pos, os.SEEK_SET)
        return size_self

    def getSizeInByte(self) -> int:
        size_self = self.getSizeInBit() / 8
        # If it is not integer
        if not size_self.is_integer():
            raise BufferError(f"The string buffer has some error that space is {self.getSizeInBit()} bit.")

        return size_self

    def resize(self, mem_in_byte: int) -> int:
        return self.truncate(mem_in_byte)


class StringMakerFromBytes:
    ...


class StringMakerFromBytes:
    """
    This is the util that makes strings from bytes.
    You can append bytes to it, and try to extract if there is any string.

    Bytes will be stored in the buffer, and if it can be a string,
    it will be decode to string, and save to string buffer `decoded_string`.
    """

    def __init__(self, encoding="utf-8", *,
                 estimate_str_buffer_size: int = 20) -> None:
        self.encoding = encoding
        self.bytes_buffer: deque[int] = deque(maxlen=10)
        self.decoded_string = deque(maxlen=estimate_str_buffer_size)

    def appendInt(self, x: int) -> StringMakerFromBytes:
        self.bytes_buffer.append(x)

        return self

    def appendBytes(self, byte_arr: bytes) -> StringMakerFromBytes:
        for b in byte_arr:
            self.bytes_buffer.append(b)

        return self

    def decode(self) -> StringMakerFromBytes:
        """
        Try to decode possible combination.
        """
        match self.encoding:
            case "utf-8": return self.decodeInUTF8()
            case _: raise TypeError(f"Got unexpected encoding here \"{self.encoding}\"")

    def decodeInUTF8(self) -> StringMakerFromBytes:
        while len(self.bytes_buffer) > 0:
            first_byte = self.bytes_buffer[0]

            # One byte character
            if first_byte & 0b1_0000000 == 0:
                s = chr(self.bytes_buffer.popleft())
            else:
                # Two byte character
                if first_byte & 0b111_00000 == 0b110_00000:
                    if len(self.bytes_buffer) >= 2:
                        byte_to_pop = 2
                    else:
                        break
                # Three byte character
                elif first_byte & 0b1111_0000 == 0b1110_0000:
                    if len(self.bytes_buffer) >= 3:
                        byte_to_pop = 3
                    else:
                        break
                # Four byte character
                elif first_byte & 0b11111_000 == 0b11110_000:
                    if len(self.bytes_buffer) >= 4:
                        byte_to_pop = 4
                    else:
                        break
                # Five byte character
                elif first_byte & 0b111111_00 == 0b111110_00:
                    if len(self.bytes_buffer) >= 5:
                        byte_to_pop = 5
                    else:
                        break
                # Six byte character
                elif first_byte & 0b1111111_0 == 0b1111110_0:
                    if len(self.bytes_buffer) >= 6:
                        byte_to_pop = 6
                    else:
                        break
                else:
                    raise ValueError(f"Unsupported byte {first_byte}")

                s = bytes([self.bytes_buffer.popleft() for _ in range(byte_to_pop)]).decode(self.encoding)

            # Add to buffer
            self.decoded_string.append(s)

        return self

    def extract(self) -> str:
        """
        This will read decoded string. If none, it can read nothing.

        This should not have too long string here.
        If so, please extract more frequently.
        """
        extracted_str_len = len(self.decoded_string)

        if extracted_str_len > 0:
            extracted_str = "".join([self.decoded_string.popleft() for _ in range(extracted_str_len)])
            self.decoded_string.clear()
            return extracted_str
        else:
            return ""
