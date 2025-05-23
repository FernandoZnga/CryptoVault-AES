from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import struct
import argparse
import hashlib
import os

SECTOR_SIZE = 512
NONCE_SIZE = 12  # 96 bits is recommended for GCM
TAG_SIZE = 16    # 128 bits authentication tag


def prepare_encryption_key(master_key):
    assert len(master_key) in (16, 24, 32), "Use a 128, 192, or 256-bit key"
    return master_key


def derive_key_from_password(password, key_length=32):
    """
    Derive a key of specified length from a password.
    Uses SHA-256 to ensure the key is of the correct length.

    Args:
        password: The password string or bytes
        key_length: Length of the key in bytes (16, 24, or 32 for AES)

    Returns:
        A bytes object of the specified length
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Use SHA-256 to get a 32-byte key
    key = hashlib.sha256(password).digest()

    # Truncate or pad the key to the desired length
    return key[:key_length]


def encrypt_volume(input_path, output_path, master_key):
    key = prepare_encryption_key(master_key)

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        sector_index = 0
        while True:
            block = fin.read(SECTOR_SIZE)
            if not block:
                break
            if len(block) < SECTOR_SIZE:
                block += b'\x00' * (SECTOR_SIZE - len(block))

            # Create a unique nonce for each sector
            # We use sector_index as part of the nonce to ensure uniqueness
            nonce = get_random_bytes(8) + struct.pack('<I', sector_index)

            # Initialize GCM mode cipher with key and nonce
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            # Add sector_index as associated data for additional authentication
            cipher.update(struct.pack('<Q', sector_index))

            # Encrypt the block and get the tag
            ciphertext, tag = cipher.encrypt_and_digest(block)

            # Write nonce, ciphertext, and authentication tag to output file
            fout.write(nonce)
            fout.write(ciphertext)
            fout.write(tag)

            sector_index += 1


def decrypt_volume(input_path, output_path, master_key):
    key = prepare_encryption_key(master_key)

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        sector_index = 0
        while True:
            # Read nonce, ciphertext and tag for this sector
            nonce = fin.read(NONCE_SIZE)
            if not nonce or len(nonce) < NONCE_SIZE:
                break  # End of file or partial read

            ciphertext = fin.read(SECTOR_SIZE)
            if not ciphertext or len(ciphertext) < SECTOR_SIZE:
                break  # Incomplete sector

            tag = fin.read(TAG_SIZE)
            if not tag or len(tag) < TAG_SIZE:
                break  # Incomplete tag

            try:
                # Initialize GCM mode cipher with key and nonce
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                # Add sector_index as associated data for authentication
                cipher.update(struct.pack('<Q', sector_index))

                # Decrypt and verify the ciphertext
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

                # Write the decrypted data
                fout.write(plaintext)

            except (ValueError, KeyError) as e:
                # Authentication failed or other decryption error
                print(f"Error decrypting sector {sector_index}: {e}")
                fout.close()
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False

            sector_index += 1

    return True


def strip_padding(input_path, output_path):
    """Remove trailing null bytes from the file."""
    with open(input_path, 'rb') as fin:
        data = fin.read().rstrip(b'\x00')
    with open(output_path, 'wb') as fout:
        fout.write(data)


def decode_hex(input_path, output_path):
    """Decode a hex‑encoded file back into raw bytes."""
    # Read hex text, remove whitespace/newlines
    with open(input_path, 'r') as fin:
        hex_str = ''.join(fin.read().split())
    raw = bytes.fromhex(hex_str)
    with open(output_path, 'wb') as fout:
        fout.write(raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Volume encrypt/decrypt/strip/decode")
    parser.add_argument(
        "mode", choices=["encrypt", "decrypt", "strip", "decode"])
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument(
        "--key", help="Master key for encrypt/decrypt", default=None)
    args = parser.parse_args()

    if args.mode == "encrypt":
        assert args.key, "--key required for encrypt"
        key = derive_key_from_password(args.key)
        encrypt_volume(args.input, args.output, key)
    elif args.mode == "decrypt":
        assert args.key, "--key required for decrypt"
        key = derive_key_from_password(args.key)
        success = decrypt_volume(args.input, args.output, key)
        if not success:
            print(
                "Decryption failed: The provided key was incorrect or the file is corrupted.")
    elif args.mode == "strip":
        strip_padding(args.input, args.output)
    elif args.mode == "decode":
        decode_hex(args.input, args.output)

    print(f"Done: {args.mode} -> {args.output}")
