from setuptools import setup

setup(
    name="encrypt-volume",
    version="0.1.0",
    description="A tool for encrypting and decrypting volumes",
    author="Fernando",
    py_modules=["encrypt_volume"],
    install_requires=[
        "pycryptodomex",  # Using Cryptodome for encryption
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
