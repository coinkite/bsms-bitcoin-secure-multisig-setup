#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Used with permission from <https://github.com/scgbckbone/btc-hd-wallet/tree/master/btc_hd_wallet>
#

from bsms.util import ser_compact_size, int_to_little_endian


def raw_serialize(script) -> bytes:
    result = b""
    for cmd in script:
        # If the command is an integer, we know that’s an opcode.
        if type(cmd) == int:
            result += int_to_little_endian(cmd, 1)
        else:
            length = len(cmd)
            if length < 75:
                # length between 1 - 75 inclusive,
                # we encode the length as a single byte.
                result += int_to_little_endian(length, 1)
            elif 75 < length < 256:
                # For any element with length from 76 to 255,
                # we put OP_PUSHDATA1 first, then encode the length
                # as a single byte, followed by the element.
                result += int_to_little_endian(76, 1)
                result += int_to_little_endian(length, 1)
            elif 256 <= length <= 520:
                # For an element with a length from 256 to 520,
                # we put OP_PUSHDATA2 first, then encode the length
                # as two bytes in little endian, followed by the element.
                result += int_to_little_endian(77, 1)
                result += int_to_little_endian(length, 2)
            else:
                # Any element longer than 520 bytes cannot be serialized.
                raise ValueError("too long an cmd")
            # actual element appending
            result += cmd
    return result


def serialize(self) -> bytes:
    result = self.raw_serialize()
    # Script serialization starts with the length of the entire script.
    return ser_compact_size(len(result)) + result
