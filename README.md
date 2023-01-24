# Bitcoin Secure Multisig Setup (BSMS)

[BIP-129](https://github.com/bitcoin/bips/blob/15c8203eb36304efa1e4588b950f62a5bb32f965/bip-0129.mediawiki)

Reference implementation is in module `bsms.bip129` and encryption primitives in `bsms.encryption`.

### Installation
```shell
pip install --upgrade pip wheel
pip install git+https://github.com/coinkite/bsms-bitcoin-secure-multisig-setup.git@master#egg=bsms-bitcoin-secure-multisig-setup
```

### Usage
```python
from bsms import CoordinatorSession, Signer

coordinator = CoordinatorSession(M=2, N=2, script_type="p2wsh", encryption="STANDARD")
session_data = coordinator.custom_session_data(["a54044308ceac9b7"])
s1 = Signer(token=session_data[0][0], key_description="Signer 1 key", master_fp="b7868815",
            wif="KyKvR9kf8r7ZVtdn3kB9ifipr6UKnTNTpWJkGZbHwARDCz5iZ39E",
            pub="xpub6FA5rfxJc94K1kNtxRby1hoHwi7YDyTWwx1KUR3FwskaF6HzCbZMz3zQwGnCqdiFeMTPV3YneTGS2YQPiuNYsSvtggWWMQpEJD4jXU7ZzEh",
            path="48'/0'/0'/2'")
s1_ciphertext = s1.round_1()
s2 = Signer(token=session_data[0][0], key_description="Signer 2 key", master_fp="eedff89a",
            wif="Kz1ijnkDXmc65NWTYdg47DDaQgSGJAPfhJG9Unm36oqZPpPXuNR6",
            pub="xpub6EhJvMneoLWAf8cuyLBLQiKiwh89RAmqXEqYeFuaCEHdHwxSRfzLrUxKXEBap7nZSHAYP7Jfq6gZmucotNzpMQ9Sb1nTqerqW8hrtmx6Y6o",
            path="48'/0'/0'/2'")
s2_ciphertext = s2.round_1()
descriptor_record = coordinator.round_2([s1_ciphertext, s2_ciphertext])[0]
s1.round_2(descriptor_record)
s2.round_2(descriptor_record)
# more examples can be found in bsms/test.py
```
Or can be used with signer keys generated on the fly:
```python
from bsms import CoordinatorSession, Signer

coordinator = CoordinatorSession(M=2, N=2, script_type="p2sh-p2wsh", encryption="EXTENDED", testnet=True)
coordinator.generate_token_key_pairs()
signers = []
for i, (token, _) in enumerate(coordinator.session_data):
    s = Signer(token=token, key_description="key%d" % i, testnet=True)
    signers.append(s)
key_records = []
for signer in signers:
    key_records.append(signer.round_1())
descriptor_records = coordinator.round_2(key_records)
for signer, desc_record in zip(signers, descriptor_records):
    signer.round_2(desc_record)
```

### Run test vectors
```shell
python3 test.py
```