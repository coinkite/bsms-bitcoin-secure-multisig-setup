#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#


import struct
import hashlib


HARDENED = 0x8000_0000


def hash160(s: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def big_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_big_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


def ser_compact_size(l):
    if l < 253:
        return struct.pack("B", l)
    elif l < 0x10000:
        return struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        return struct.pack("<BI", 254, l)
    else:
        return struct.pack("<BQ", 255, l)


def bitcoin_msg(message):
    xmsg = b'\x18Bitcoin Signed Message:\n' + ser_compact_size(len(message)) + message.encode()
    md = hashlib.sha256(hashlib.sha256(xmsg).digest()).digest()
    return md


def path_component_in_range(num: int) -> bool:
    # cannot be less than 0
    # cannot be more than (2 ** 31) - 1
    if 0 <= num < HARDENED:
        return True
    return False


def str2path(path):
    # normalize notation and return numbers, limited error checking
    rv = []

    for i in path.split('/'):
        if i == 'm':
            continue
        if not i:
            # trailing or duplicated slashes
            continue

        if i[-1] in "'phHP":
            if len(i) < 2:
                raise ValueError(f"Malformed bip32 path component: {i}")
            num = int(i[:-1], 0)
            if not path_component_in_range(num):
                raise ValueError(f"Hardened path component out of range: {i}")
            here = num | HARDENED
        else:
            here = int(i, 0)
            if not path_component_in_range(here):
                # cannot be less than 0
                # cannot be more than (2 ** 31) - 1
                raise ValueError(f"Non-hardened path component out of range: {i}")

        rv.append(here)

    return rv
