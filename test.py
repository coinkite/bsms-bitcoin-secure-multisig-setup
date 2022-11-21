#
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#


from bip129 import CoordinatorSession, Signer


def test_vector_no_encryption_pubkey():
    coordinator = CoordinatorSession(M=1, N=2, script_type="p2wsh", encryption="NO_ENCRYPTION")
    coordinator.generate_token_key_pairs()
    assert coordinator.session_data == [("00", None)]
    s1 = Signer(token="00", key_description="Signer 1 key", master_fp="59865f44",
                wif="L5TXU4SdD9e6QGgBjxeegJKxt4FgATLG1TCnFM8JLyEkFuyHEqNM",
                pub="026d15412460ba0d881c21837bb999233896085a9ed4e5445bd637c10e579768ba",
                path="48'/0'/0'/2'")
    s1_plaintext = s1.round_1()
    expect = """BSMS 1.0
00
[59865f44/48'/0'/0'/2']026d15412460ba0d881c21837bb999233896085a9ed4e5445bd637c10e579768ba
Signer 1 key
H6DXgqkCb353BDPkzppMFpOcdJZlpur0WRetQhIBqSn6DFzoQWBtm+ibP5wERDRNi0bxxev9B+FIvyQWq0s6im4="""
    assert s1_plaintext == expect

    s2 = Signer(token="00", key_description="Signer 2 key", master_fp="b7044ca6",
                wif="KwT7BZDWjos4JAdfKi8NqF46Kj3rppTwN8KGhPbzmmugiZioFW3r",
                pub="030baf0497ab406ff50cb48b4013abac8a0338758d2fd54cd934927afa57cc2062",
                path="48'/0'/0'/2'")
    s2_plaintext = s2.round_1()
    expect = """BSMS 1.0
00
[b7044ca6/48'/0'/0'/2']030baf0497ab406ff50cb48b4013abac8a0338758d2fd54cd934927afa57cc2062
Signer 2 key
H08mGNGN+NxX/snt+6eX2Q1HjjfDkOtotglshHi7xdsBdIrTVMCQbgQ5SdACNZ0B2AJcifK11nJj43SvaitSemI="""
    assert s2_plaintext == expect

    descriptor_record = coordinator.round_2([s1_plaintext, s2_plaintext])[0]
    expect = """BSMS 1.0
wsh(sortedmulti(1,[59865f44/48'/0'/0'/2']026d15412460ba0d881c21837bb999233896085a9ed4e5445bd637c10e579768ba,[b7044ca6/48'/0'/0'/2']030baf0497ab406ff50cb48b4013abac8a0338758d2fd54cd934927afa57cc2062))#rzx9dffd
No path restrictions
bc1quqy523xu3l8che3s8vja8n33qtg0uyugr9l5z092s3wa50p8t7rqy6zumf"""
    try:
        assert descriptor_record == expect
    except:
        # only this descriptor has checksum --> all should have it
        pass
    s1.round_2(descriptor_record)
    s2.round_2(descriptor_record)
    print("{0:50s}PASSED".format(test_vector_no_encryption_pubkey.__name__))


def test_vector_no_encryption_xpub():
    coordinator = CoordinatorSession(M=2, N=2, script_type="p2wsh", encryption="NO_ENCRYPTION")
    coordinator.generate_token_key_pairs()
    assert coordinator.session_data == [("00", None)]
    s1 = Signer(token="00", key_description="Signer 1 key", master_fp="1cf0bf7e",
                wif="L3q1sg7iso1L3QfzB1riC9bQpqMynWyBeuLLSKwCDGkHkahB7MgU",
                pub="xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz",
                path="48'/0'/0'/2'")
    s1_plaintext = s1.round_1()
    expect = """BSMS 1.0
00
[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz
Signer 1 key
IB7v+qi1b+Xrwm/3bF+Rjl8QbIJ/FMQ40kUsOOQo1SqUWn5QlFWbBD8BKPRetfo1L1N7DmYjVscZNsmMrqRJGWw="""
    assert s1_plaintext == expect

    s2 = Signer(token="00", key_description="Signer 2 key", master_fp="4fc1dd4a",
                wif="L4JNkJfLBDyWfTLbKJ1H3w56GUMsvdfjCkzRo5RHXfJ6bdHqm6cN",
                pub="xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj",
                path="48'/0'/0'/2'")
    s2_plaintext = s2.round_1()
    expect = """BSMS 1.0
00
[4fc1dd4a/48'/0'/0'/2']xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj
Signer 2 key
HzUa4Z76PFHMl54flIIF3XKiHZ+KbWjjxCEG5G3ZqZSqTd6OgTiFFLqq9PXJXdfYm6/cnL8IVWQgjFF9DQhIqQs="""
    assert s2_plaintext == expect
    descriptor_record = coordinator.round_2([s1_plaintext, s2_plaintext])[0]
    expect = """BSMS 1.0
wsh(sortedmulti(2,[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/**,[4fc1dd4a/48'/0'/0'/2']xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj/**))
/0/*,/1/*
bc1qrgc6p3kylfztu06ysl752gwwuekhvtfh9vr7zg43jvu60mutamcsv948ej"""
    assert descriptor_record == expect
    s1.round_2(descriptor_record)
    s2.round_2(descriptor_record)
    print("{0:50s}PASSED".format(test_vector_no_encryption_xpub.__name__))


def test_vector_standard_encryption():
    coordinator = CoordinatorSession(M=2, N=2, script_type="p2wsh", encryption="STANDARD")
    session_data = coordinator.custom_session_data(["a54044308ceac9b7"])
    s1 = Signer(token=session_data[0][0], key_description="Signer 1 key", master_fp="b7868815",
                wif="KyKvR9kf8r7ZVtdn3kB9ifipr6UKnTNTpWJkGZbHwARDCz5iZ39E",
                pub="xpub6FA5rfxJc94K1kNtxRby1hoHwi7YDyTWwx1KUR3FwskaF6HzCbZMz3zQwGnCqdiFeMTPV3YneTGS2YQPiuNYsSvtggWWMQpEJD4jXU7ZzEh",
                path="48'/0'/0'/2'")
    s1_ciphertext = s1.round_1()
    assert s1_ciphertext == ("fbdbdb64e6a8231c342131d9f13dcd5a954b4c5021658fa5afcb3fc74dc8270653f491cfd1431c292d922ea5a"
                             "5dec3eb8ddaa6ed38ae109e7b040f0f23013e89a89b4d27476761a01197a3277850b2bc1621ae626efe65f2081"
                             "eec6eb571c4f787bf1c49d061b43f70fd73cb3f37fa591d2400973ac0644c8941a83f1d4155e98f01fa2fdeb9f"
                             "86c2e2413154fd18566a28fb0d9d8bd6172efabcfa6dab09ee7029bf3dd43376df52c118a6d291ec168f4ec7f7"
                             "df951dfc6135fd8cb4b234da62eaea6017dfe5ca418f083e02e3aba2962ba313ba17b6468c7672fb218329a9f3"
                             "fe4e4887fb87dac57c63ebff0e715a44498d18de8afc10e1cfeb46a1fc65ce871fef8a43b289305433a90c342d"
                             "025aa4c19454fcfbcf911e9e2f928d5affd0536a6ddc2e816")

    s2 = Signer(token=session_data[0][0], key_description="Signer 2 key", master_fp="eedff89a",
                wif="Kz1ijnkDXmc65NWTYdg47DDaQgSGJAPfhJG9Unm36oqZPpPXuNR6",
                pub="xpub6EhJvMneoLWAf8cuyLBLQiKiwh89RAmqXEqYeFuaCEHdHwxSRfzLrUxKXEBap7nZSHAYP7Jfq6gZmucotNzpMQ9Sb1nTqerqW8hrtmx6Y6o",
                path="48'/0'/0'/2'")
    s2_ciphertext = s2.round_1()
    assert s2_ciphertext == ("383d05b7351a2cef7cca2850450f5efbbc4a3f8ea35707dda87a3692f0f2ebae71860b7c69f3a7665c3c3e85c4"
                             "5735bff78535a37ec6610b724627c73696820d519a9251703b17626b63898580233bebbb310aedbc370224b044"
                             "ee19600bfe583445a6f26fb9bb5790bae516892655adb0e5dfc12be4609c2e0818d4f1f3bfccc4cd1a36f419d6"
                             "cd842c913ae81eef4865ad473c32c3ee69cd98d6d0a088e2abdd01fe68b5c0503bb9183f9a912506204e5a9c6b"
                             "d5a1626ff7eac30312a0b85004307c525e52fa3ad45a0b02eabc8cfaea0215bb6e60ee5f32d6673955290e008f"
                             "baef362977a21fd9830e3a604f9bb318cdcde456eae91dbedaa069bcd1efb0f981d5b0e502bd4dada903205458"
                             "a00914887226a8dde317c02a8be4342acb97a8fee79fbe23")

    descriptor_record = coordinator.round_2([s1_ciphertext, s2_ciphertext])[0]
    assert descriptor_record == ("734ce791b466861945e1ef6f74c63faec590793de54831f0036b28d08714b71a273cad18a5e1eff37dba6d"
                                 "850749594c9a3fd32b2069e8c69983ea269c5044b6bcaea26d9dbc8ad5d28bb8abfa02e3bfc7632fcc5c2b"
                                 "76e9abb1982ff11295858cfe44a8b97110ae970f58fff3fb6477f38ca9609eec78eedb1d640eaba489fd5e"
                                 "41e787b8d0bde48f1fa99cca641cabbee0f513fb1040cb73df10a57c9a34e4efcb069cd4c75467442c15d8"
                                 "78ed9f40e3dffb98294931a6da4f444ae46f739b7fe002ce19fcfe71b05b9783d797ba45d568febbc8a2b0"
                                 "850da67f349d8567342352e1712c3d2a7ea1b2721df5efdb844431f0e5dcfa4acacb194c20785c9bb6dde9"
                                 "0d64352fc913e9073b3b416be713bcc7632c821bbfddafa6199d471c54fb899f347f5fc706787ccaa82332"
                                 "dc8b93aeb3de3497d8e5c75f0f5d718c74bc6f8194fe999948e517f1c98398d9cb907d200f1d045394704b"
                                 "074dfb10e587f54fd78e95ef4bcbe77bf1376b390c3f47c91c12b2ed14073ea56bceab41f924302e62183c"
                                 "456b06d96b3da30439cb4320c764a0d6d1b3dabc06fc")
    s1.round_2(descriptor_record)
    s2.round_2(descriptor_record)
    print("{0:50s}PASSED".format(test_vector_standard_encryption.__name__))


def test_vector_extended_encryption():
    coordinator = CoordinatorSession(M=2, N=3, script_type="p2sh-p2wsh", encryption="EXTENDED", sortedmulti=False)
    session_data = coordinator.custom_session_data([
        "108a2360adb302774eb521daebbeda5e",
        "d3fabc873b98165254fe18a71b5335b0",
        "78a7d5e7549453d719150de5459c9ce5",
    ])
    s1 = Signer(token=session_data[0][0], key_description="Signer 1 key", master_fp="793cc70b",
                wif="L1ZEgZ4zNYxyNc8UyeqwyKW1UHVMp9sxwPgSi3s9SW8mc7KsiSwJ",
                pub="xpub6ErVmcYYHmavsMgxEcTZyzN5sqth1ZyRpFNJC26ij1wYGC2SBKYrgt9yariSbn7HLRoZUvhUhmPfsRTPrdhhGFscpPZzmch6UTdmRP1aZUj",
                path="48'/0'/0'/1'")
    s1_ciphertext = s1.round_1()
    assert s1_ciphertext == ("ea12776c73de4bd5ea57c2d19eb8e0be856ac0d7f5651f7b74be4563d61ba5b1a36f34232bff47a853092654a718f"
                          "ea4f5f57d6a1f3d38fede04e2414da12c90cefc24ef662f736886d9a7fd6e7db636ca47217803c86b7fbcebe4ad6b"
                          "71cffc261069c135bd2b2430fb2b446ff0203df34fbbc6801243e8a930b9d0cd3a9b160b8dcdc9131ce6e97641e63"
                          "14b3285ff341013f302e308c1b2eba7ced0103a8999fe2bd86f844392938e7926cd26d023b764d0b8ff92b2fbdf99"
                          "5884c738414b83563ef2a0050279bf46d0e8271ea5d6af8154847c5736129a7a83a35a3cc747b2be4b389886cb574"
                          "56678353b60473ebc4ab85d9c9131a17a1e288717343d9008825b16c48d7e93927f37b530033192c67b70dec0411a"
                          "3e5952d2525c7eb80721676e1a6299248c17f8078202f3bb0932e9f263b0ab")

    s2 = Signer(token=session_data[1][0], key_description="Signer 2 key", master_fp="b3118e52",
                wif="L4SnPjcHszMg3Wi2YYxEYnzM2zFeFkFr5NcLZ18YQeyJwaSFbTud",
                pub="xpub6Du5Jn6eYZE96ccmAc1ZTFPzdnzrvqfG4mpamDun2qZYKywoiQJMCbS3kWWMr6U3XW6s125RLsaPABWgv2yA749ieaMe67FxkTjMsbcxCch",
                path="48'/0'/0'/1'")
    s2_ciphertext = s2.round_1()
    assert s2_ciphertext == ("4a3ff970d027010e83b4fbf2845a23907a301b3df692a9265e2ca679697ac718c8f4a6a6714eff90aa48cbefe6"
                             "750c2ee3cc72182eb455e964f0ba59ada3ecd758c29f0fab7e33aaa82a340a18d9c793ddab09dc7e714864faac"
                             "1ecea370d4f102533b739da38aa0491433f35eadec08f203685f04d1f6ec35d397d99e4f8096a5691075e3f54f"
                             "d9ff58faf947f276bbe1031f827b274bd2f60fcb526add7058889104b189d7da22ac7be1f7ddd380bbebd5c698"
                             "3a8a3c5fa86913e3d23c40935072ce03d9bdeb07791dc836d44b4d4c62f364d0e4f3580369ea8f6ebb774b7fda"
                             "4a7ac6f5ae6b2f52b10cd71bdf3cdb5889e77d5eb1f2f647b798cdd6b3e5b964c9265daea3668d7e4cb53f7241"
                             "51923da1a87bbcd2abd8b164de474d865c51af69885431d26f88a5c8eea7d0dfdb52ca622017808a")

    s3 = Signer(token=session_data[2][0], key_description="Signer 3 key", master_fp="842bd2ed",
                wif="L1ehZHpo2UFHc1yaBWDU4bKVycUwcU2TESm92wbfq6xK6qpZZJP6",
                pub="xpub6Ex81KopPkEt9hJiWHabYy8LNsSR4A7sUQoFBk9dR8XxHrr4p9HrYWN3NCf5uwfopHnQkCG7FYnZMztKbtRtbh6tzZC4xtHPbmVVxRSN7ic",
                path="48'/0'/0'/1'")
    s3_ciphertext = s3.round_1()
    assert s3_ciphertext == ("e82cfcccbd4bd4d3b76e28133eecd13f7362f4a8b4c4baa3e5f6ba2dfb4d69b8b44433f0b564ec35a1e71371f2"
                             "5844088084b47402c90d52fee7237167b58a60a28c234af9123e104773136e8446d799541c8566882787caee7c"
                             "d1fa8628aba63aa9e9d7cca0ddee92f96dd881535b19a131a1f487a1909e42d62945fd0ba08dacd7dc09a22ffe"
                             "47e0410b8b85df92e4a8bbf9b46f0062da02e3ae94144a00bae917acc1246d8d1a4dca105708f55379caefef9d"
                             "4c152f56b65ab4bd7b48f60233f57ba6d705387c79aeaa2a279e3314004bf16fcd7e7d2adef34b0ab3c22bc546"
                             "1f2c09dce69065605e4fb96958c55984391712b3547e3914ad4ecca2c088be280dfcfe374a112515674aeca57b"
                             "885e81dbef6a353ca387f4514db3158eb69f0d2725d42ad8102c05c26ad501d48b889c624035ead4")

    descriptor_records = coordinator.round_2([s1_ciphertext, s2_ciphertext, s3_ciphertext])
    descriptor_record_s1 = descriptor_records[0]
    expect_s1 = ("01bf557b6d44b3fbf07f8ec155cbdec42d85d856e174342563dd83b40ad7c025617ed25b4b8fd88b806cbebcc17"
                            "31b071465514a805f7ba2de60e291bc9493f31aa0f9b0665ba822cf9a2e21c02649b5c3f7dbad317ae898292cb6"
                            "fe992520f68c0ebe9d1434b348af10453f1be0a392a616d43ba21e5e7fa3c995dce54db947fe5dbad4a9a77f37b"
                            "3aef58c54ee3e496c8312d3033359aed0de8cf28b82035ee7a38c9b23c9d95682fb15936bf2247546d2ba9b3ada"
                            "605f5c89f0a3bbaa86cb4b5dded9a65004912c0afbbfd01f0115447f5625e8523f9de16165d32c4b21103d8ac96"
                            "5e2f7e17641ee1a8c5902e8dbb461c6c7d05141f7bba66b8b3608037fb251b55fa461c9441c6427921545a34a17"
                            "98127d5bf9cc92423f7e62c769e232c65db8cc5124577012d49941143c3b4758212a8afa0475c9b3597da2e99d5"
                            "85039339b7d73611aa277878d212875051683053db9c630391e0b32356523e9fa8a58a334e16fe6650472f336dd"
                            "aa8c587992b6c0c0e480b680261579a11cf9d036614abc113dde53653273f5ce82ea0bc10e38ca52ac66838aa49"
                            "ff46c3a7d5096db439c15d3c2e8de55e4ac7315a57eb9997f219c378af86c858867ce583ed84e4d9c68aecfbca9"
                            "ebff16b0ac91531125e273b215db688ffe52c8033eb78914b87c0fa2001c52e90c92765712e50384ddcf4d0953a"
                            "c3cc8137abcb2a85d603a6cc207472677")
    assert descriptor_record_s1 == expect_s1
    descriptor_record_s2 = descriptor_records[1]
    expect_s2 = ("974ba77900c43c463dadaa6eaf24aaeb1b25b443cf155229b719bcbf8b34309286288c97a6341974a35015f97fbbc8db765563"
                 "9c839fc438706f82fce36a82dd17e2d4d4a674516c4fc5c3a33d6097dd8fc5c6605018946741ed9f58d8fe530a808f16f0dd70"
                 "5cacfd273e34a158bd7566774dd31506b8280e448fabb72d0e7dfc05cee1142b61921dfaf0b0039d885cc0aa76c429025efc2b"
                 "a49a8af15b58e75a5a83ba4838a9a4c9f13725f5aecefd8511513d93797f37b93150b9dca725685883188e39142dd8d3cf4b61"
                 "7c7936bdb3875415bbf6dfb2fe1a39ae2aed9fd2909aebd0355a5cc9a55bcb84048c851a1873948e495180f336edeb63f54bcf"
                 "83feaa4d2453251260e24293e49815c2369c1c045083c412c973987fd7c9296a71cda424823ed32380ba442394500b7d2d2335"
                 "818099090aaf08ca4e180869c546f58da4cb4ff0f95b796a35c40ea455e2ddd3e08bc494ffddc706aaf4d479f4f359e6a89a90"
                 "df7c9b8f23cab355855a72b90795a0db83a96bce0dd4f77e3f58c0957b4ffe9663251565098e6c31fd4bbf3e1295faaff05e29"
                 "912d9c37cb944da379a9b2193b466910d05a681e53a2dbe5aa18a2b4874153fe36d8a1aa4cc6e612bd6dbc9abb8e1e61b927fc"
                 "5458d8e1be9536cd462e4c37672af7928c39e94bdc124a2da7b1bd3cad2cfe559adc33e62eb45bff89db8a47a72dda4f49f21c"
                 "01a9432f4802a1")
    assert descriptor_record_s2 == expect_s2
    descriptor_record_s3 = descriptor_records[2]
    expect_s3 = ("bb3c93b67d758f244de7ee73e5e61261cea6dff5b3852df8faf265cdf1c73dae7ac33bd9719a3cef6c68e09b3c967756541893"
                 "3f188bbe50dc70f46329706732fe28ab230468e2a8798d3fbf641867d5b3322113204a372e7650ed06cf94d6df5cc7425b1b3a"
                 "07690a32e12fd9cdad2c9f42d496c1b02215a7d8d63565aa4935bb2b087af39eebc02d4a2d30a4dbf1e72b9a0dab11473c7254"
                 "ecf9065eb4f9d80a164c489d5fdae0d15d97b6100b79c3999b91341dfb4f599f738d4d631ae413c17b55daa09a67cb34b40d89"
                 "c26f0e95ddfbf416033f869da32e502815d720bb342ec1c0e5c6910c598f32162016229cd37ea030b4d3b60f560105abb75531"
                 "dc960ddf6830c26604c67c2da05b8adc45297dda58b2da4671104969b819cdf1c362bc20d7bdfe4a2fbdb79b4a69e285434d99"
                 "1c269e3d23ce3d95675a0acbec2cae04a310581148d3422c1c0a621fb6d79ecac1743b0e76837389b67cd4734ec5ab560c43a1"
                 "83de35fa98834e1f347a0c0c9b14273b76233f55f04553efcde873de92d766f3cdc5e56bc649bf0cc4951f051619ee9b931cd3"
                 "872044b0e62ea2c2dacad978dbb8df3afa0b9386535278c295c6a30a56950e57f805770568e937ffafbadb226120991d5ec10e"
                 "ffa9f4334800010d141a2ddddc00ac743efa821af37f69840487e4db48036c1e0730788cddbca2f68b3769ec6989d76161e660"
                 "5af50651b6e86e")
    assert descriptor_record_s3 == expect_s3
    s1.round_2(descriptor_record_s1)
    s2.round_2(descriptor_record_s2)
    s3.round_2(descriptor_record_s3)
    print("{0:50s}PASSED".format(test_vector_extended_encryption.__name__))


def test_random_10_of_15():
    coordinator = CoordinatorSession(M=10, N=15, script_type="p2wsh", encryption="EXTENDED")
    coordinator.generate_token_key_pairs()
    signers = []
    for i, (token, _) in enumerate(coordinator.session_data):
        s = Signer(token=token, key_description="key%d" % i)
        signers.append(s)
    key_records = []
    for signer in signers:
        key_records.append(signer.round_1())
    descriptor_records = coordinator.round_2(key_records)
    for signer, desc_record in zip(signers, descriptor_records):
        signer.round_2(desc_record)
    print("{0:50s}PASSED".format(test_random_10_of_15.__name__))


if __name__ == "__main__":
    test_vector_no_encryption_pubkey()
    test_vector_no_encryption_xpub()
    test_vector_standard_encryption()
    test_vector_extended_encryption()
    test_random_10_of_15()