import os
import pytest
import tempfile
import hashlib
import random
import string
from pathlib import Path
import sys

# Add parent directory to path so we can import the module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encrypt_volume import (
    prepare_encryption_key,
    derive_key_from_password,
    encrypt_volume,
    decrypt_volume,
    strip_padding
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


@pytest.fixture
def test_key():
    """Generate a test encryption key."""
    return os.urandom(32)  # 256-bit key


@pytest.fixture
def test_password():
    """Generate a test password."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


@pytest.fixture
def test_file(temp_dir):
    """Create a test file with random content."""
    file_path = os.path.join(temp_dir, "test_file.txt")
    
    # Create a file with 5 KB of random data
    with open(file_path, 'wb') as f:
        f.write(os.urandom(5 * 1024))
    
    return file_path


@pytest.fixture
def binary_test_file(temp_dir):
    """Create a binary test file (simulating an image)."""
    file_path = os.path.join(temp_dir, "test_image.png")
    
    # Create a fake PNG file header followed by random data
    with open(file_path, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')
        # Some random data simulating image content
        f.write(os.urandom(10 * 1024))
    
    return file_path


class TestKeyDerivation:
    """Tests for key derivation functions."""
    
    def test_prepare_encryption_key(self, test_key):
        """Test that prepare_encryption_key accepts valid keys."""
        # 32-byte key (256 bits)
        key = prepare_encryption_key(test_key)
        assert key == test_key
        
        # 16-byte key (128 bits)
        short_key = test_key[:16]
        key = prepare_encryption_key(short_key)
        assert key == short_key
        
        # 24-byte key (192 bits)
        medium_key = test_key[:24]
        key = prepare_encryption_key(medium_key)
        assert key == medium_key
    
    def test_prepare_encryption_key_invalid(self):
        """Test that prepare_encryption_key rejects invalid keys."""
        # 10-byte key (80 bits) - invalid length
        invalid_key = os.urandom(10)
        with pytest.raises(AssertionError):
            prepare_encryption_key(invalid_key)
    
    def test_derive_key_from_password(self, test_password):
        """Test key derivation from password."""
        # Default length (32 bytes)
        key = derive_key_from_password(test_password)
        assert len(key) == 32
        assert key == hashlib.sha256(test_password.encode()).digest()
        
        # Custom length
        key_16 = derive_key_from_password(test_password, key_length=16)
        assert len(key_16) == 16
        assert key_16 == hashlib.sha256(test_password.encode()).digest()[:16]


class TestEncryptionDecryption:
    """Tests for encryption and decryption functionality."""
    
    def test_basic_encryption_decryption(self, temp_dir, test_key, test_file):
        """Test basic encryption and decryption of a text file."""
        # Setup file paths
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        decrypted_file = os.path.join(temp_dir, "decrypted.txt")
        
        # Encrypt the file
        encrypt_volume(test_file, encrypted_file, test_key)
        assert os.path.exists(encrypted_file)
        
        # Encrypted file should be different from original
        with open(test_file, 'rb') as f1, open(encrypted_file, 'rb') as f2:
            assert f1.read() != f2.read()
        
        # Decrypt the file
        assert decrypt_volume(encrypted_file, decrypted_file, test_key)
        assert os.path.exists(decrypted_file)
        
        # Compare original and decrypted files
        with open(test_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
            original_data = f1.read()
            decrypted_data = f2.read().rstrip(b'\x00')  # Remove padding
            assert original_data == decrypted_data
    
    def test_binary_file_encryption(self, temp_dir, test_key, binary_test_file):
        """Test encryption and decryption of a binary file."""
        # Setup file paths
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        decrypted_file = os.path.join(temp_dir, "decrypted.png")
        final_file = os.path.join(temp_dir, "final.png")
        
        # Encrypt the file
        encrypt_volume(binary_test_file, encrypted_file, test_key)
        
        # Decrypt the file
        decrypt_volume(encrypted_file, decrypted_file, test_key)
        
        # Strip padding
        strip_padding(decrypted_file, final_file)
        
        # Compare original and final files
        with open(binary_test_file, 'rb') as f1, open(final_file, 'rb') as f2:
            assert f1.read() == f2.read()
    
    def test_wrong_key_decryption(self, temp_dir, test_file):
        """Test decryption with wrong key fails properly."""
        # Setup file paths
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        decrypted_file = os.path.join(temp_dir, "decrypted.txt")
        
        # Use two different keys
        correct_key = os.urandom(32)
        wrong_key = os.urandom(32)
        
        # Encrypt with correct key
        encrypt_volume(test_file, encrypted_file, correct_key)
        
        # Decrypt with wrong key should fail
        result = decrypt_volume(encrypted_file, decrypted_file, wrong_key)
        assert result is False  # Decryption should fail
        assert not os.path.exists(decrypted_file)  # File should be deleted on failure


class TestFileHandling:
    """Tests for file handling functionality."""
    
    def test_large_file_handling(self, temp_dir, test_key):
        """Test handling of larger files with multiple sectors."""
        # Create a larger test file (1 MB)
        large_file = os.path.join(temp_dir, "large_file.dat")
        with open(large_file, 'wb') as f:
            f.write(os.urandom(1024 * 1024))
        
        encrypted_file = os.path.join(temp_dir, "large_encrypted.bin")
        decrypted_file = os.path.join(temp_dir, "large_decrypted.dat")
        
        # Encrypt and decrypt
        encrypt_volume(large_file, encrypted_file, test_key)
        decrypt_volume(encrypted_file, decrypted_file, test_key)
        
        # Verify the content
        with open(large_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
            # Read in chunks to handle large files
            chunk_size = 8192
            while True:
                chunk1 = f1.read(chunk_size)
                chunk2 = f2.read(chunk_size)
                
                if not chunk1:
                    # End of file 1, make sure file 2 doesn't have extra content
                    # excluding padding
                    remaining = f2.read().rstrip(b'\x00')
                    assert not remaining
                    break
                    
                if not chunk2:
                    # File 2 ended before file 1
                    assert False, "Decrypted file is truncated"
                
                if chunk1 != chunk2.rstrip(b'\x00'):
                    # Only compare with padding removed from the last chunk
                    if f1.peek(1) == b'':  # Last chunk
                        assert chunk1 == chunk2.rstrip(b'\x00')
                    else:
                        assert chunk1 == chunk2
    
    def test_nonexistent_input_file(self, temp_dir, test_key):
        """Test handling of nonexistent input file."""
        nonexistent_file = os.path.join(temp_dir, "nonexistent.txt")
        output_file = os.path.join(temp_dir, "output.bin")
        
        # Attempt to encrypt a nonexistent file
        with pytest.raises(FileNotFoundError):
            encrypt_volume(nonexistent_file, output_file, test_key)


class TestPaddingHandling:
    """Tests for padding handling."""
    
    def test_strip_padding(self, temp_dir):
        """Test the strip_padding function."""
        # Create a file with deliberate padding
        padded_file = os.path.join(temp_dir, "padded.txt")
        stripped_file = os.path.join(temp_dir, "stripped.txt")
        
        original_content = b"This is a test content"
        padded_content = original_content + b'\x00' * 20
        
        with open(padded_file, 'wb') as f:
            f.write(padded_content)
        
        # Strip padding
        strip_padding(padded_file, stripped_file)
        
        # Verify content
        with open(stripped_file, 'rb') as f:
            assert f.read() == original_content
    
    def test_different_sector_sizes(self, temp_dir, test_key):
        """Test handling of files with sizes not multiple of sector size."""
        for size in [100, 512, 513, 1000, 1024]:
            # Create files of different sizes
            test_file = os.path.join(temp_dir, f"test_{size}.dat")
            encrypted_file = os.path.join(temp_dir, f"enc_{size}.bin")
            decrypted_file = os.path.join(temp_dir, f"dec_{size}.dat")
            final_file = os.path.join(temp_dir, f"final_{size}.dat")
            
            # Create test file with exact size
            with open(test_file, 'wb') as f:
                f.write(os.urandom(size))
            
            # Encrypt, decrypt and strip
            encrypt_volume(test_file, encrypted_file, test_key)
            decrypt_volume(encrypted_file, decrypted_file, test_key)
            strip_padding(decrypted_file, final_file)
            
            # Verify content
            with open(test_file, 'rb') as f1, open(final_file, 'rb') as f2:
                assert f1.read() == f2.read()

