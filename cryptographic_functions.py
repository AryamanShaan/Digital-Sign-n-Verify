import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as assymetric_padding



def hash_pdf(pdf_data: bytes) -> str:

    sha256_hash = hashlib.sha256(pdf_data).digest() # digest should output bytes

    return sha256_hash


def generate_rsa_key_pair():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Generate the public key from the private key
    public_key = private_key.public_key()
    
    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Unencrypted private key (will encrypt it later)
    )
    
    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem



def encrypt_with_private_key(data, private_key_pem):
    """Encrypts data with an RSA private key."""

    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )

    encrypted_data = private_key.encrypt(
        data,
        assymetric_padding.OAEP(
            mgf=assymetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_data



def decrypt_with_public_key(encrypted_data, public_key_pem):
    """Decrypts data with an RSA public key."""

    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )

    try:
        decrypted_data = public_key.decrypt(
            encrypted_data,
            assymetric_padding.OAEP(
                mgf=assymetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_data
    except ValueError:
        return None # Decryption failed.


def encrypt_private_key(aes_key, private_key_pem):
    # Generate a random IV (Initialization Vector) for AES encryption
    iv = os.urandom(16)
    
    # Create AES cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the private key to be a multiple of 16 bytes (AES block size)
    # pad_length = 16 - len(private_key_pem) % 16
    # padded_private_key = private_key_pem + bytes([pad_length]) * pad_length

    padder = symmetric_padding .PKCS7(128).padder()
    padded_private_key = padder.update(private_key_pem) + padder.finalize()

    # Encrypt the private key
    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()
    
    return encrypted_private_key, iv

def decrypt_private_key(aes_key, encrypted_private_key, iv):
    # Create AES cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the private key
    decrypted_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()
    
    # Remove padding from the decrypted private key
    # pad_length = decrypted_private_key[-1]p
    # decrypted_private_key = decrypted_private_key[:-pad_length]

    unpadder = symmetric_padding.PKCS7(128).unpadder()
    decrypted_private_key = unpadder.update(decrypted_private_key) + unpadder.finalize()
    
    return decrypted_private_key
