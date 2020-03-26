import struct


def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))


class SHA1:
    def __init__(self, data=b''):
        self.h = [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
                ]
        self.remainder = data
        self.count = 0

    def _add_chunk(self, chunk):
        self.count += 1
        w = list(struct.unpack(">16I", chunk) + (None,) * (80-16))
        for i in range(16, 80):
            n = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w[i] = leftrotate(n, 1)
        a, b, c, d, e = self.h
        for i in range(80):
            f = None
            k = None
            if i < 20:
                f = (b & c) ^ (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + w[i]) % 2**32
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        self.h[0] = (self.h[0] + a) % 2**32
        self.h[1] = (self.h[1] + b) % 2**32
        self.h[2] = (self.h[2] + c) % 2**32
        self.h[3] = (self.h[3] + d) % 2**32
        self.h[4] = (self.h[4] + e) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b''
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk(message[chunk:chunk+64])
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.add(b'\x80' + b'\x00' * ((55 - l) % 64) +
                 struct.pack(">Q", l * 8))
        h = tuple(x for x in self.h)
        self.__init__()
        return struct.pack(">5I", *h)


class class__evil_SHA1:

    def __init__(self, data, sha_state, prev_len):

        self.prev_len = prev_len

        a = int.from_bytes(sha_state[0:4], 'big')
        b = int.from_bytes(sha_state[4:8], 'big')
        c = int.from_bytes(sha_state[8:12], 'big')
        d = int.from_bytes(sha_state[12:16], 'big')
        e = int.from_bytes(sha_state[16:20], 'big')

        self.h = [a, b, c, d, e]
        self.remainder = data
        self.count = 0

    def _add_chunk(self, chunk):
        self.count += 1
        w = list(struct.unpack(">16I", chunk) + (None,) * (80-16))
        for i in range(16, 80):
            n = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w[i] = leftrotate(n, 1)
        a, b, c, d, e = self.h
        for i in range(80):
            f = None
            k = None
            if i < 20:
                f = (b & c) ^ (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + w[i]) % 2**32
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

        self.h[0] = (self.h[0] + a) % 2**32
        self.h[1] = (self.h[1] + b) % 2**32
        self.h[2] = (self.h[2] + c) % 2**32
        self.h[3] = (self.h[3] + d) % 2**32
        self.h[4] = (self.h[4] + e) % 2**32

    def add(self, data):
        message = self.remainder + data
        print(f"Msg: {message}")
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b''
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk(message[chunk:chunk+64])
        return self

    def finish(self):
        l = self.prev_len + len(self.remainder) + 64 * self.count
        self.add(b'\x80' + b'\x00' * ((55 - l) % 64) +
                 struct.pack(">Q", l * 8))
        h = tuple(x for x in self.h)
        # self.__init__(self.data, self.sha_state)
        return struct.pack(">5I", *h)
