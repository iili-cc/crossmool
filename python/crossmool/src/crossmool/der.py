"""
Minimal DER reader to parse SPKI (X.509) and PKCS8 used by crossmool JS/Java utils.
This is a small port of the project's JS `DerReader` used to extract raw EC keys.
"""
from typing import Tuple


class DerReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.len = len(data)

    def _read_length(self) -> int:
        first = self._read(1)[0]
        if first & 0x80 == 0:
            return first
        num = first & 0x7F
        val = 0
        for _ in range(num):
            val = (val << 8) | self._read(1)[0]
        return val

    def _read(self, n: int) -> bytes:
        if self.pos + n > self.len:
            raise ValueError('Truncated DER')
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_sequence(self) -> 'DerReader':
        tag = self._read(1)[0]
        if tag != 0x30:
            raise ValueError('Expected SEQUENCE')
        length = self._read_length()
        content = self._read(length)
        return DerReader(content)

    def read_integer_bytes(self) -> bytes:
        tag = self._read(1)[0]
        if tag != 0x02:
            raise ValueError('Expected INTEGER')
        length = self._read_length()
        return self._read(length)

    def read_oid(self) -> str:
        tag = self._read(1)[0]
        if tag != 0x06:
            raise ValueError('Expected OID')
        length = self._read_length()
        oid_bytes = self._read(length)
        # decode OID
        first = oid_bytes[0]
        oid_nodes = [str(first // 40), str(first % 40)]
        value = 0
        for b in oid_bytes[1:]:
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                oid_nodes.append(str(value))
                value = 0
        return '.'.join(oid_nodes)

    def read_bit_string(self) -> Tuple[int, bytes]:
        tag = self._read(1)[0]
        if tag != 0x03:
            raise ValueError('Expected BIT STRING')
        length = self._read_length()
        content = self._read(length)
        unused_bits = content[0]
        data = content[1:]
        return unused_bits, data

    def read_octet_string(self) -> bytes:
        tag = self._read(1)[0]
        if tag != 0x04:
            raise ValueError('Expected OCTET STRING')
        length = self._read_length()
        return self._read(length)

    def read(self, n: int) -> bytes:
        return self._read(n)

    def eof(self) -> bool:
        return self.pos >= self.len
