from __future__ import print_function

from kmip.core import enums

import binascii
import struct
import time


class DecodeTTLV(object):
    def __init__(self, buffer):
        self.offset = 0
        self.buffer = buffer
        self.indent = ""
        self.nest = []
        self.type_map = {
            'DEFAULT': self._decode_type_default,
            'STRUCTURE': self._decode_type_struct,
            'INTEGER': self._decode_type_int4,
            'LONG_INTEGER': self._decode_type_long,
            'BIG_INTEGER': self._decode_type_bigint,
            'ENUMERATION': self._decode_type_enum,
            'BOOLEAN': self._decode_type_bool,
            'TEXT_STRING': self._decode_type_text,
            'BYTE_STRING': self._decode_type_bytes,
            'DATE_TIME': self._decode_type_date,
            'INTERVAL': self._decode_type_inter,
        }

    def decode(self):
        while self.offset < len(self.buffer):
            self.indent = " " * len(self.nest)

            tag_val = self._decode_tag()
            type_val = self._decode_type()
            size_val = self._decode_size()
            value = self.type_map[type_val](tag_val, size_val)

            print("{0}{1}:{2}({3}):{4}".format(
                self.indent, tag_val, type_val, size_val, value))

            if len(self.nest):
                if self.offset == self.nest[-1]:
                    self.nest = self.nest[:-1]
                    self.indent = " " * len(self.nest)

    def _decode_tag(self):
        fmt = ">Bh"
        tag = struct.unpack_from(fmt, self.buffer, self.offset)
        if tag[0] != 0x42:
            print(binascii.hexlify(self.buffer[self.offset:]))
            raise Exception(
                ("bad tag {0},{1} at offset {2}"
                 .format(hex(tag[0]), hex(tag[1]), self.offset)))

        tag = (int(tag[0]) << 16) | int(tag[1])
        out = self._get_enum_name('Tags', tag)
        self.offset += 3
        return out

    def _decode_type(self):
        fmt = ">B"
        val = struct.unpack_from(fmt, self.buffer, self.offset)[0]
        out = self._get_enum_name('Types', val)
        self.offset += 1
        return out

    def _decode_size(self):
        fmt = ">I"
        val = struct.unpack_from(fmt, self.buffer, self.offset)[0]
        self.offset += 4
        return val

    def _decode_type_default(self, tag, size):
        raise Exception(("default value found in buffer at {0}"
                        .format(self.offset)))

    def _decode_type_struct(self, tag, size):
        self.nest.append(self.offset + size)
        return "stru{0}".format(len(self.nest))

    def _decode_type_int4(self, tag, size):
        fmt = ">i"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size + 4  # 4 bytes padding
        return val[0]

    def _decode_type_long(self, tag, size):
        fmt = ">q"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size  # 8
        return val[0]

    def _decode_type_bigint(self, tag, size):
        fmt = ">q"  # FIXME(tkelsey): this is wrong
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size  # variable
        return val[0]

    def _decode_type_enum(self, tag, size):
        fmt = ">I"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size + 4  # 4 bytes padding
        return self._get_enum_name(tag, val[0])

    def _decode_type_bool(self, tag, size):
        fmt = ">Q"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size  # variable
        return (val[0] != 0)

    def _decode_type_text(self, tag, size):
        val = self.buffer[self.offset:self.offset+size]
        self.offset += size + (8 - size % 8) % 8  # padded to mutliple of 8
        return unicode(val)

    def _decode_type_bytes(self, tag, size):
        val = self.buffer[self.offset:self.offset+size]
        self.offset += size + (8 - size % 8) % 8  # padded to mutliple of 8
        return binascii.hexlify(val)

    def _decode_type_date(self, tag, size):
        fmt = ">L"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size  # variable
        return time.ctime(val[0])

    def _decode_type_inter(self, tag, size):
        fmt = ">i"
        val = struct.unpack_from(fmt, self.buffer, self.offset)
        self.offset += size + 4  # 4 bytes padding
        return val[0]

    def _get_enum_name(self, tag, val):
        type_name = ''.join(x.capitalize() or '_' for x in tag.split('_'))
        enum = getattr(enums, type_name)
        for name in dir(enum):
            enum_val = getattr(enum, name)
            if isinstance(enum_val, enum) and enum_val.value == val:
                return enum_val.name


if __name__ == '__main__':
    import sys
    bindata = ""
    testdata = sys.argv[1]

    for i in range(0, len(testdata)/2):
        a = testdata[i*2]
        b = testdata[i*2+1]
        bindata += struct.pack(">B", int(a+b, 16))

    bindata = bytearray(bindata)
    decoder = DecodeTTLV(bindata)
    decoder.decode()
