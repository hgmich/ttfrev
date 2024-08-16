from typing import Optional
from construct import Subconstruct, stream_tell, stream_read, stream_read_entire, SizeofError
import io



# backport from construct
class BytesIOWithOffsets(io.BytesIO):
    @staticmethod
    def from_reading(stream, length: int, path: str):
        offset = stream_tell(stream, path)
        contents = stream_read(stream, length, path)
        return BytesIOWithOffsets(contents, stream, offset)

    def __init__(self, contents: bytes, parent_stream, offset: int):
        super().__init__(contents)
        self.parent_stream = parent_stream
        self.parent_stream_offset = offset

    def tell(self) -> int:
        return super().tell() + self.parent_stream_offset

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence != io.SEEK_SET:
            super().seek(offset, whence)
        else:
            super().seek(offset - self.parent_stream_offset)
        return self.tell()


def rol32(x, n):
    if n == 0:
        return x
    elif n < 0:
        raise ValueError("cannot rotate negative (use ror32)")
    shift_mask = ((1 << 32) - 1) ^ (1 << (32 - n) - 1)
    shift_out = x & shift_mask
    x <<= n
    x &= 0xFFFFFFFF
    shift_in = shift_out >> (32 - n)
    return (x | shift_in) & 0xFFFFFFFF


PACK_EXE_KEY = 0x1E177CE
SPACE_EXE_KEY = 0x312A4CE


def xor_crypt(bs: bytes, key: int):
    """
    A custom cipher used for protecting CBIN files
    
    The algorithm is a standard XOR crypt cipher w/ a rotating 4 byte key.
    """
    out = bytearray()
    print(f"XOR Crypting {len(bs)} bytes with key {key}")
    for b in bs:
        key = rol32(key, 7)
        out.append((b ^ (key & 0xFF)) & 0xFF)
    return bytes(out)


class XorCrypted(Subconstruct):
    """
    Wraps a field that is "encrypted" with the simple XOR cipher.
    """

    key: int
    size: Optional[int]

    def __init__(self, subcon, key: int = PACK_EXE_KEY, size: Optional[int] = None):
        super(XorCrypted, self).__init__(subcon)

        self.key = key
        self.size = size
    
    def _parse(self, stream, context, path):
        key = self.key(context) if callable(self.key) else self.key
        try:
            d_len = self._sizeof(context, path)
        except SizeofError:
            d_len = None
        d_len = self._sizeof(context, path)
        offset = stream_tell(stream, path)

        if d_len is not None:
            data = stream_read(stream, d_len, path)
        else:
            data = stream_read_entire(stream, path)
        data = xor_crypt(data, key)
        substream = BytesIOWithOffsets(data, stream, offset)

        return self.subcon._parsereport(substream, context, path)

    def _build(self, obj, stream, context, path):
        key = self.key(context) if callable(self.key) else self.key
        d_len = self._sizeof(context, path)
        offset = stream_tell(stream, path)
        stream2 = io.BytesIO()
        buildret = self.subcon._build(obj, stream2, context, path)

        data = stream2.getvalue()
        data = xor_crypt(data, key)
        stream_write(stream, data, len(data), path)
        return buildret

    def _sizeof(self, context, path):
        if self.size is not None:
            return self.size(context) if callable(self.size) else self.size

        try:
            return self.subcon._sizeof(context, path)
        except SizeofError:
            return None


def hex_or_dec_int(s: str) -> int:
    if s.startswith("0x"):
        return int(s[2:], 16)
    else:
        return int(s)