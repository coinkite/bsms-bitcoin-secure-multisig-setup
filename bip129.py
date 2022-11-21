#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

import os
import base64

from base58 import decode_base58_checksum, encode_base58_checksum
from util import bitcoin_msg, str2path
from bip32 import PrvKeyNode, PubKeyNode
from ecdsa import ecdsa_sign, ecdsa_verify, ecdsa_recover
from address import p2wsh_address, p2sh_p2wsh_address
from encryption import key_derivation_function, encrypt, decrypt


BSMS_VERSION = "BSMS 1.0"


script2desc_sortedmulti = {
    # "p2sh": "sh(sortedmulti(%d,%s))",
    "p2sh-p2wsh": "sh(wsh(sortedmulti(%d,%s)))",
    "p2wsh": "wsh(sortedmulti(%d,%s))"
}

script2desc_multi = {
    # "p2sh": "sh(sortedmulti(%d,%s))",
    "p2sh-p2wsh": "sh(wsh(multi(%d,%s)))",
    "p2wsh": "wsh(multi(%d,%s))"
}


class CoordinatorSession:
    def __init__(self, M, N, script_type, encryption="NO_ENCRYPTION", sortedmulti=True, path_restrictions="/0/*,/1/*"):
        self.M = M
        self.N = N
        self.script_type = script_type.lower()
        assert self.script_type in list(script2desc_sortedmulti.keys())
        self.encryption = encryption.upper()
        assert self.encryption in ["NO_ENCRYPTION", "STANDARD", "EXTENDED"]
        self.sortedmulti = sortedmulti
        self.path_restrictions = path_restrictions
        self.session_data = None

    def __repr__(self):
        return "%d of %d %s encryption=%s" % (
            self.M,
            self.N,
            self.script_type,
            self.encryption
        )

    def is_extended_encryption(self):
        return self.encryption == "EXTENDED"

    def is_standard_encryption(self):
        return self.encryption == "STANDARD"

    def is_without_encryption(self):
        return self.encryption == "NO_ENCRYPTION"

    @staticmethod
    def generate_token(bits=128):
        return os.urandom(int(bits/8)).hex()

    def custom_session_data(self, tokens):
        res = []
        for token in tokens:
            key = key_derivation_function(token)
            res.append((token, key))
        self.session_data = res
        return self.session_data

    def generate_token_key_pairs(self):
        if self.is_without_encryption():
            res = [("00", None)]
        elif self.is_standard_encryption():
            token = self.generate_token(bits=64)
            key = key_derivation_function(token)
            res = [(token, key)]
        else:
            assert self.is_extended_encryption()
            res = []
            for _ in range(self.N):
                token = self.generate_token()
                key = key_derivation_function(token)
                res.append((token, key))

        self.session_data = res
        return self.session_data

    def first_from_path_restrictions(self):
        first = self.path_restrictions.split(",")[0]
        return [int(num) if num != "*" else 0 for num in first.split("/") if num]

    def round_2(self, key_records):
        assert len(set(key_records)) == self.N
        decrypted_key_records = []
        if self.is_extended_encryption():
            # needs to get records in order to know which key to use
            for i, record in enumerate(key_records):
                decrypted = decrypt(self.session_data[i][1], record)
                decrypted_key_records.append(decrypted)
        elif self.is_standard_encryption():
            for record in key_records:
                decrypted = decrypt(self.session_data[0][1], record)
                decrypted_key_records.append(decrypted)
        else:
            decrypted_key_records = key_records
        bsms_versions = set()
        extended_keys = []
        nodes = []
        secs = []
        is_xpub = True
        for record in decrypted_key_records:
            version, token, key_exp, description, sig = record.split("\n")
            bsms_versions.add(version)
            pub = key_exp[key_exp.find("]") + 1:]
            if pub[:4] in ["xpub", "tpub"]:
                parsed_xpub = PubKeyNode.parse(pub)
                parsed_sec = parsed_xpub.sec()
                nodes.append(parsed_xpub)
            else:
                # pubkeys SEC (compressed)
                assert pub[:2] in ["03", "02"]
                parsed_sec = bytes.fromhex(pub)
                secs.append(parsed_sec)
                is_xpub = False
            signed_data = "\n".join([version, token, key_exp, description])
            signed_digest = bitcoin_msg(signed_data)
            decoded_sig = base64.b64decode(sig)
            recovered_sec = ecdsa_recover(bitcoin_msg(signed_data), decoded_sig)
            assert recovered_sec == parsed_sec
            assert ecdsa_verify(signed_digest, decoded_sig, parsed_sec), "Signature invalid"
            if is_xpub:
                extended_keys.append(key_exp + "/**")
            else:
                extended_keys.append(key_exp)

        assert len(bsms_versions) == 1, "Different BSMS version"
        result = "%s\n" % BSMS_VERSION
        if self.sortedmulti:
            mapping = script2desc_sortedmulti
        else:
            mapping = script2desc_multi
        desc_template = mapping[self.script_type]
        descriptor = desc_template % (self.M, ",".join(extended_keys))
        result += "%s\n" % descriptor
        if not is_xpub:
            path_restrictions = "No path restrictions"
        else:
            path_restrictions = self.path_restrictions
        result += "%s\n" % path_restrictions

        if not secs:
            # secs are empty only if we have xpubs
            for node in nodes:
                derived = node.derive_path(self.first_from_path_restrictions())
                secs.append(derived.sec())

        if self.script_type == "p2wsh":
            address = p2wsh_address(secs, self.M, sortedmulti=self.sortedmulti)
        else:
            address = p2sh_p2wsh_address(secs, self.M, sortedmulti=self.sortedmulti)
        result += address

        results = []
        if self.is_extended_encryption():
            for token, key in self.session_data:
                res = encrypt(key, token, result)
                results.append(res)
        elif self.is_standard_encryption():
            token, key = self.session_data[0]
            res = encrypt(key, token, result)
            results.append(res)
        else:
            # no encryption
            results.append(result)
        return results


class Signer:
    def __init__(self, token, key_description, master_fp=None, wif=None, pub=None, path="48'/0'/0'/2'"):
        self.token = token
        self.key_description = key_description
        assert len(key_description) <= 80
        self.path = path
        self.encryption_key = key_derivation_function(token) if token != "00" else None
        if wif is None and pub is None and master_fp is None:
            # generate new
            m = PrvKeyNode.master_key(os.urandom(64))
            self.master_fp = m.fingerprint().hex()
            ext_prv = m.derive_path(str2path(self.path))
            self.sk = ext_prv.key
            self.wif = self.serialize_wif()
            self.pub = ext_prv.extended_public_key()
        else:
            assert wif is not None and pub is not None
            self.wif = wif
            self.sk = self.parse_wif()
            self.pub = pub
            self.master_fp = master_fp

    def parse_wif(self):
        decoded = decode_base58_checksum(s=self.wif)
        if self.wif[0] in ("K", "L", "c"):
            # compressed key --> so remove last byte that has to be 01
            assert decoded[-1] == 1
            decoded = decoded[:-1]
        return decoded[1:]

    def serialize_wif(self, compressed=True, testnet=False):
        prefix = b"\xef" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        return encode_base58_checksum(prefix + bytes(self.sk) + suffix)

    def desc_type_key(self):
        return "[%s/%s]%s" % (self.master_fp, self.path, self.pub)

    def round_1(self):
        result = "%s\n" % BSMS_VERSION
        result += "%s\n" % self.token
        result += "%s\n" % self.desc_type_key()
        result += "%s" % self.key_description
        sig = base64.b64encode(ecdsa_sign(bitcoin_msg(result), self.sk)).decode()
        result += "\n" + sig
        if self.encryption_key:
            result = encrypt(self.encryption_key, self.token, result)
        return result

    def round_2(self, descriptor_record):
        if self.encryption_key:
            decrypted = decrypt(self.encryption_key, descriptor_record)
            descriptor_record = decrypted

        version, descriptor, path_restrictions, addr = descriptor_record.split("\n")
        # The Signer verifies that it can support the included specification version.
        assert version == BSMS_VERSION
        # The Signer verifies that it can support the descriptor or descriptor template.

        # The Signer checks that its KEY is included in the descriptor or descriptor template, using path and fingerprint
        # information provided. The check must perform an exact match on the KEYs and not using shortcuts such as matching
        # fingerprints, which is trivial to spoof.
        assert self.desc_type_key() in descriptor
        # The Signer verifies that it is compatible with the derivation path restrictions.
        sortedmulti = True
        script_type = None
        # The Signer verifies that the wallet's first address is valid.
        if descriptor.startswith("wsh(sortedmulti("):
            res = descriptor.replace("wsh(sortedmulti(", "")
            res = res[:-2]  # trailing parenthesis
            script_type = "p2wsh"
        elif descriptor.startswith("sh(wsh(sortedmulti("):
            res = descriptor.replace("sh(wsh(sortedmulti(", "")
            res = res[:-3]  # trailing parenthesis
            script_type = "p2sh-p2wsh"
        elif descriptor.startswith("wsh(multi("):
            res = descriptor.replace("wsh(multi(", "")
            res = res[:-2]  # trailing parenthesis
            sortedmulti = False
            script_type = "p2wsh"
        elif descriptor.startswith("sh(wsh(multi("):
            res = descriptor.replace("sh(wsh(multi(", "")
            res = res[:-3]  # trailing parenthesis
            sortedmulti = False
            script_type = "p2sh-p2wsh"
        else:
            raise ValueError("unknown script type")

        inner = res.split(",")
        M, key_expressions = int(inner[0]), inner[1:]
        secs = []
        for ke in key_expressions:
            ke = ke.replace("/**", "")
            pub = ke[ke.find("]") + 1:]
            if pub[:4] in ["xpub", "tpub"]:
                ext_key = PubKeyNode.parse(pub)
                derived = ext_key.derive_path([0, 0])
                secs.append(derived.sec())
            else:
                # pubkey SEC (compressed)
                assert pub[:2] in ["03", "02"]
                derived = bytes.fromhex(pub)
                secs.append(derived)

        if script_type == "p2wsh":
            address = p2wsh_address(secs, M, sortedmulti=sortedmulti)
        else:
            address = p2sh_p2wsh_address(secs, M, sortedmulti=sortedmulti)
        assert address == addr

        # For confirmation, the Signer must display to the user the wallet's first address and policy parameters,
        # including, but not limited to: the derivation path restrictions, M, N, and the position(s)
        # of the Signer's own KEY in the policy script. The total number of Signers, N, is important to prevent a KEY insertion attack.
        # The position is important for scripts where KEY order matters. When applicable, all positions of the KEY must be displayed.
        # The full descriptor or descriptor template must also be available for review upon user request.
        # Parties must check with each other that all Signers have the same confirmation (except for the KEY positions).
        # If all checks pass, the Signer must persist the descriptor record in its storage.
