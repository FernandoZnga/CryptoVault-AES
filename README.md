# SecureEncrypt

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![Tests](https://github.com/FernandoZnga/CryptoVault-AES/actions/workflows/python-tests.yml/badge.svg)
[![codecov](https://codecov.io/gh/FernandoZnga/CryptoVault-AES/branch/main/graph/badge.svg)](https://codecov.io/gh/FernandoZnga/CryptoVault-AES)
![License](https://img.shields.io/badge/license-MIT-green)
![Security Status](https://img.shields.io/badge/security-AES--GCM-brightgreen)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
[![Code Quality](https://img.shields.io/badge/code--quality-A-brightgreen)](https://github.com/FernandoZnga/CryptoVault-AES)
![Last Commit](https://img.shields.io/github/last-commit/FernandoZnga/CryptoVault-AES?color=blue)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

A secure file encryption and decryption tool using AES-GCM mode for authenticated encryption. This tool provides a simple command-line interface for encrypting and decrypting files with strong cryptographic security.

## Academic Context

This project was developed as part of a Master's degree in Cybersecurity, specifically for the Applied Cryptography course ("Criptografía Aplicada"). It represents a component of the final project requirements, demonstrating practical application of cryptographic principles in secure software development.

## Features

- **Secure Encryption**: Uses AES-GCM (Galois/Counter Mode) for both confidentiality and data integrity
- **Password-based Key Derivation**: Securely derives encryption keys from user passwords
- **Sector-by-sector Processing**: Efficiently handles files of any size
- **Data Integrity Verification**: Automatically verifies the authenticity of encrypted data
- **File Format Preservation**: Ensures binary files (images, PDFs, etc.) can be properly decrypted

## Installation

### Prerequisites

- Python 3.6 or higher
- pycryptodomex library (core dependency)

**For development:**
- pytest (testing)
- pytest-cov (test coverage)
- flake8 (code linting)

### Steps

1. Clone the repository:
```bash
git clone https://github.com/FernandoZnga/CryptoVault-AES.git
cd CryptoVault-AES
```

2. Install the required dependencies:
```bash
# For basic usage
pip install pycryptodomex

# For development (includes testing tools)
pip install -r requirements.txt
```

## Usage

### Basic Commands

#### Encrypting a file:
```bash
python encrypt_volume.py encrypt input_file encrypted_file --key "your_password"
```

#### Decrypting a file:
```bash
python encrypt_volume.py decrypt encrypted_file decrypted_file --key "your_password"
```

#### Stripping padding from decrypted files (if needed):
```bash
python encrypt_volume.py strip decrypted_file final_file
```

#### Decoding hex-encoded files:
```bash
python encrypt_volume.py decode hex_encoded_file decoded_file
```

### Examples

Encrypt an image file:
```bash
python encrypt_volume.py encrypt photo.jpg photo.encrypted --key "secure_password_123"
```

Decrypt the image:
```bash
python encrypt_volume.py decrypt photo.encrypted photo_decrypted.jpg --key "secure_password_123"
```

## Development Setup

If you want to contribute to the project or run tests, follow these steps to set up your development environment:

1. Clone the repository and create a virtual environment:
```bash
git clone https://github.com/FernandoZnga/CryptoVault-AES.git
cd CryptoVault-AES
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install all development dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tests:
```bash
pytest
```

4. Generate coverage report:
```bash
pytest --cov=. --cov-report=term
```

5. Run linting:
```bash
flake8
```

### Continuous Integration

This project uses GitHub Actions for continuous integration:

- Tests are automatically run on multiple Python versions (3.8 - 3.12)
- Code coverage is reported to Codecov
- Linting checks are performed using flake8

You can check the current build status at the top of this README.

## Security Considerations

- **Key Management**: Passwords are converted to encryption keys using SHA-256. For even stronger security, consider using a key derivation function with salt and iterations.
- **GCM Mode**: This tool uses AES-GCM mode which provides authenticated encryption. This means it can detect if the encrypted data has been tampered with.
- **Nonce Generation**: A unique nonce is generated for each sector to ensure that identical data is encrypted differently each time.
- **Memory Management**: This tool does not store encryption keys in memory for longer than necessary.

## Limitations

- If you lose your password, there is no way to recover encrypted data.
- For very large files, the sector-by-sector approach may take some time to complete.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [pycryptodomex](https://github.com/Legrandin/pycryptodome) for the cryptographic implementation
- All contributors who help improve this project

