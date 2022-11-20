#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Used with permission from <https://github.com/scgbckbone/btc-hd-wallet/tree/master/btc_hd_wallet>
#

import hashlib
import bech32
from util import hash160
from base58 import encode_base58_checksum
from script import raw_serialize


OP_NUMBERS = {
    1: 81,
    2: 82,
    3: 83,
    4: 84,
    5: 85,
    6: 86,
    7: 87,
    8: 88,
    9: 89,
    10: 90,
    11: 91,
    12: 92,
    13: 93,
    14: 94,
    15: 95,
    16: 96,
}


def h256_to_p2wsh_address(h256: bytes, testnet: bool = False, witver: int = 0):
    hrp = "tb" if testnet else "bc"
    return bech32.encode(hrp=hrp, witver=witver, witprog=h256)


def h160_to_p2sh_address(h160: bytes, testnet: bool = False):
    prefix = b"\xc4" if testnet else b"\x05"
    return encode_base58_checksum(prefix + h160)


def p2wsh_address(secs, M, testnet=False, sortedmulti=True):
    assert M <= 15
    N = len(secs)
    assert N <= 15
    if sortedmulti:
        secs.sort()
    witness_script = [OP_NUMBERS[M], *secs, OP_NUMBERS[N], 0xae]
    sha256_witness_script = hashlib.sha256(raw_serialize(witness_script)).digest()
    return h256_to_p2wsh_address(
        h256=sha256_witness_script,
        testnet=testnet
    )


def p2sh_p2wsh_address(secs, M, testnet=False, sortedmulti=True):
    assert M <= 15
    N = len(secs)
    assert N <= 15
    if sortedmulti:
        secs.sort()
    witness_script = [OP_NUMBERS[M], *secs, OP_NUMBERS[N], 0xae]
    sha256_witness_script = hashlib.sha256(raw_serialize(witness_script)).digest()
    redeem_script = raw_serialize([0x00, sha256_witness_script])
    return h160_to_p2sh_address(
        h160=hash160(redeem_script),
        testnet=testnet
    )
