from functools import reduce
from operator import add
from collections import deque
import math


class BitExtracter:
    def __init__(self, of: object) -> None:
        self._origin = of
        self._position_by_codepoint = 0
        self._position_by_bit = 0
        self._getNBit_buffer_of_remain: deque[int] = deque()
        self._origin_str_exhausted = False

    def getNBit(self, n_bit: int) -> list[int]:
        """
        Extract n bits from the string, and return to you.

        NOTICE: if you just exhausted the string, the result will have trailing zero.
        You should always check whether the string is exhausted.
        """
        # If the string is already exhausted, should not start
        if self._origin_str_exhausted:
            raise EOFError(f"The string you want to extract is already exhausted.")

        n_bit_to_extract = n_bit
        result = [0] * n_bit_to_extract
        result_position = 0

        # If there is remained bits in the buffer, use them
        len_remaining = len(self._getNBit_buffer_of_remain)
        if len_remaining > 0:
            can_append_n_bit = min(n_bit_to_extract, len_remaining)
            while result_position < can_append_n_bit:
                result[result_position] = self._getNBit_buffer_of_remain.popleft()
                result_position += 1

            n_bit_to_extract -= can_append_n_bit

        # Extract new bytes from string if still need to append
        if n_bit_to_extract > 0:
            guess_num_of_char_extract = math.ceil(n_bit_to_extract / 8)
            extracted_byte = self._getNCharFromOrigin(guess_num_of_char_extract).encode()
            # Concat lists of bits
            bits_array = reduce(add, [BitExtracter.bytesToBits(c) for c in extracted_byte])
            bits_array_len = len(bits_array)

            # Checkpoint: `bits_array` must be longer than `n_bit`
            # If not enough length, means you have exhausted the string
            # Important: It will be filled with extra 0 at the end,
            #  since the result is filled with all 0 at the first.
            if bits_array_len < n_bit_to_extract:
                # raise BufferError(f"Requiring {n_bit} bits, but got {bits_array_len} len buffer with {bits_array}.")
                self._origin_str_exhausted = True
                n_bit_to_extract = bits_array_len

            # Extract the number that is needed
            bits_array_position = 0
            while bits_array_position < n_bit_to_extract:
                result[result_position] = bits_array[bits_array_position]
                bits_array_position += 1
                result_position += 1

            # Push the remained elements to the buffer, if any
            for i in range(bits_array_position, bits_array_len):
                self._getNBit_buffer_of_remain.append(bits_array[i])

        self._position_by_bit += len(result)

        return result

    def bytesToBits(of: bytes | int) -> list[int]:
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
                bit_length = of.bit_length()
                start_at = math.ceil(bit_length / 8) * 8 - 1
                return [(of >> weight) & 1 for weight in range(start_at, -1, -1)]

            case _:
                raise TypeError(f"Unsupported type {type(of)} for `bytesToBits`.")

    def bitsToNumber(of_bits_arr: list[int]) -> int:
        result = 0
        arr_length = len(of_bits_arr)

        for i in range(arr_length):
            if of_bits_arr[i] == 1:
                result += 1 << (arr_length - 1 - i)

        return result

    def isExhausted(self) -> bool:
        return self._origin_str_exhausted

    def isNotExhausted(self) -> bool:
        return not self._origin_str_exhausted

    def getPositionByBit(self) -> int:
        return self._position_by_bit

    def _getNCharFromOrigin(self, n_char: int) -> str:
        possible_max_position_exclude = min(self._position_by_codepoint + n_char, len(self._origin))
        result = self._origin[self._position_by_codepoint:possible_max_position_exclude]
        self._position_by_codepoint = possible_max_position_exclude
        return result
