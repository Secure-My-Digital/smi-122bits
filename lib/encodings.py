
import math
import base91
import misc.base95 as base95

BASE_ALPHABET = ''.join(chr(i) for i in range(32, 127))


class Base91:
    NAME = "Base91"
    ALPHABET_SIZE = 91

    @staticmethod
    def encode(data):
        return base91.encode(data)

    @staticmethod
    def decode(text):
        return base91.decode(text)

    @classmethod
    def bits_per_char(cls):
        return math.log2(cls.ALPHABET_SIZE)


class Base95:
    NAME = "Base95"
    ALPHABET_SIZE = len(base95.ALPHABET)

    @staticmethod
    def encode(data):
        return base95.encode(data)

    @staticmethod
    def decode(text):
        return base95.decode(text)

    @classmethod
    def bits_per_char(cls):
        return math.log2(cls.ALPHABET_SIZE)
