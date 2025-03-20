import base64
import hashlib
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
import binascii
from cryptography.exceptions import InvalidSignature

# Dictionary to store keys
keys = {}

def generate_key(key_type: str, key_size: int):
    """generate_key generates a random key of the specified type and size.
    Args:
        key_type (str): The type of the key. Supported values are "AES".
        key_size (int): The size of the key in bits. Supported values are 128, 192, and 256."""
    
    if key_type.upper() != "AES" or key_size not in [128, 192, 256]:
        raise HTTPException(status_code=400, detail="Invalid key type or size")
    key = uuid.uuid4().bytes[:key_size // 8]  # Generate random key
    key_id = str(uuid.uuid4())
    keys[key_id] = key
    return key_id, base64.b64encode(key).decode()



def encrypt(key_id: str, plaintext: str, algorithm: str):
    """encrypt encrypts the plaintext using the specified key and algorithm.
    Args:
        key_id (str): The ID of the key to use for encryption.
        plaintext (str): The plaintext to encrypt.
        algorithm (str): The encryption algorithm to use. Supported values are "AES"."""
    
    key = keys.get(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if algorithm.upper() != "AES":
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    
    iv = uuid.uuid4().bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Proper PKCS7 Padding
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits (16 bytes)
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()




def decrypt(key_id: str, ciphertext: str, algorithm: str):
    """decrypt decrypts the ciphertext using the specified key and algorithm.
    Args:
        key_id (str): The ID of the key to use for decryption.
        ciphertext (str): The ciphertext to decrypt.
        algorithm (str): The encryption algorithm to use. Supported values are "AES"."""
    
    key = keys.get(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if algorithm.upper() != "AES":
        raise HTTPException(status_code=400, detail="Unsupported algorithm")

    try:
        decoded_data = base64.b64decode(ciphertext)
        iv, ciphertext = decoded_data[:16], decoded_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Proper PKCS7 Unpadding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()

    except (ValueError, binascii.Error, InvalidSignature):
        raise HTTPException(status_code=400, detail="Decryption failed: Invalid ciphertext or padding error.")


def generate_hash(data: str, algorithm: str):
    """generate_hash generates a hash of the data using the specified algorithm.
    Args:
        data (str): The data to hash.
        algorithm (str): The hash algorithm to use. Supported values are "SHA-256" and "SHA-512"."""
    
    if algorithm.upper() not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    hash_func = hashes.SHA256() if algorithm.upper() == "SHA-256" else hashes.SHA512()
    digest = hashlib.new(hash_func.name, data.encode()).digest()
    return base64.b64encode(digest).decode(), algorithm.upper()

def verify_hash(data: str, hash_value: str, algorithm: str):
    """verify_hash verifies the hash of the data using the specified algorithm."
    "Args:
        data (str): The data to verify.
        hash_value (str): The hash value to compare against.
        algorithm (str): The hash algorithm to use. Supported values are "SHA-256" and "SHA-512"."""
    
    generated_hash = generate_hash(data, algorithm)[0]
    is_valid = generated_hash == hash_value
    return is_valid, "Hash matches the data." if is_valid else "Hash mismatch."