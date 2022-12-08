
# (c) Copyright 2022 by Coinkite Inc. All rights reserved..

from setuptools import setup


requirements = [
    'pyaes',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='bsms-bitcoin-secure-multisig-setup',
    version="0.0.1",
    packages=[
        'bsms',
    ],
    python_requires='>3.6.0',
    install_requires=requirements,
    url='https://github.com/coinkite/bsms-bitcoin-secure-multisig-setup',
    author='Coinkite Inc.',
    author_email='support@coinkite.com',
    description="Bitcoin Secure Multisig Setup ( BIP-0129 )",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
    ],
)