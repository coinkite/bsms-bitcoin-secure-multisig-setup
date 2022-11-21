#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

import hmac
import pyaes
import hashlib


SHA512 = "sha512"


def key_derivation_function(token):
    key = hashlib.pbkdf2_hmac(
        hash_name=SHA512,
        password=b"No SPOF",
        salt=bytes.fromhex(token),
        iterations=2048,
        dklen=32,
    )
    return key


def hmac_key(key):
    return hashlib.sha256(key).digest()


def m_a_c(key, token, data):
    mac_key = hmac.new(key=key, msg=(token + data).encode(), digestmod=hashlib.sha256).digest()
    return mac_key


def aes_256_ctr_encrypt(key, iv, plaintext):
    aes_encrypt = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(int(iv.hex(), 16)))
    ciphertext = aes_encrypt.encrypt(plaintext)
    ciphertext_str = ciphertext.hex()
    return ciphertext_str


def aes_256_ctr_decrypt(key, iv, ciphertext):
    aes_decrypt = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(int(iv.hex(), 16)))
    plaintext = aes_decrypt.decrypt(ciphertext)
    plaintext = plaintext.decode()
    return plaintext


def decrypt(key, data):
    record = bytes.fromhex(data)
    mac, ciphertext = record[:32], record[32:]
    iv = mac[:16]
    decrypted = aes_256_ctr_decrypt(key, iv, ciphertext)
    return decrypted


def encrypt(key, token, data):
    hmac_k = hmac_key(key)
    mac = m_a_c(hmac_k, token, data)
    iv = mac[:16]
    ciphertext = aes_256_ctr_encrypt(key, iv, data)
    return mac.hex() + ciphertext
