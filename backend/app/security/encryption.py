"""
Encryption Engine - AES-256 encryption with PBKDF2 key derivation
"""
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

class EncryptionEngine:
    """Handles AES-256 encryption/decryption with PBKDF2 key derivation."""
    
    # Constants
    KEY_SIZE = 32  # 256 bits
    IV_SIZE = 16   # 128 bits for AES
    SALT_SIZE = 32
    PBKDF2_ITERATIONS = 100000  # OWASP recommendation
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation."""
        return secrets.token_bytes(EncryptionEngine.SALT_SIZE)
    
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from master password using PBKDF2.
        
        Args:
            master_password: User's master password
            salt: Random salt for key derivation
            
        Returns:
            32-byte encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=EncryptionEngine.KEY_SIZE,
            salt=salt,
            iterations=EncryptionEngine.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        return kdf.derive(master_password.encode())
    
    @staticmethod
    def encrypt_password(password: str, master_password: str, salt: bytes) -> bytes:
        """
        Encrypt a password using AES-256-CBC.
        
        Args:
            password: Password to encrypt
            master_password: User's master password
            salt: Salt for key derivation
            
        Returns:
            Encrypted password with IV prepended
        """
        # Derive encryption key
        key = EncryptionEngine.derive_key(master_password, salt)
        
        # Generate random IV
        iv = secrets.token_bytes(EncryptionEngine.IV_SIZE)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Pad password to block size (16 bytes for AES)
        padded_password = EncryptionEngine._pad(password.encode())
        
        # Encrypt
        encrypted = encryptor.update(padded_password) + encryptor.finalize()
        
        # Prepend IV to encrypted data (IV is not secret)
        return iv + encrypted
    
    @staticmethod
    def decrypt_password(encrypted_data: bytes, master_password: str, salt: bytes) -> str:
        """
        Decrypt a password using AES-256-CBC.
        
        Args:
            encrypted_data: Encrypted password with IV prepended
            master_password: User's master password
            salt: Salt for key derivation
            
        Returns:
            Decrypted password
        """
        # Derive encryption key
        key = EncryptionEngine.derive_key(master_password, salt)
        
        # Extract IV (first 16 bytes)
        iv = encrypted_data[:EncryptionEngine.IV_SIZE]
        encrypted = encrypted_data[EncryptionEngine.IV_SIZE:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        
        # Decrypt
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        # Remove padding
        unpadded = EncryptionEngine._unpad(decrypted)
        
        return unpadded.decode()
    
    @staticmethod
    def _pad(data: bytes) -> bytes:
        """PKCS7 padding to block size."""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def generate_secure_password(length: int = 16, 
                                 use_uppercase: bool = True,
                                 use_lowercase: bool = True,
                                 use_digits: bool = True,
                                 use_symbols: bool = True) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Password length
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            
        Returns:
            Random secure password
        """
        import string
        
        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            raise ValueError("At least one character type must be selected")
        
        # Use secrets for cryptographically secure random
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        return password