import base64
import hashlib
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException

# Dictionary to store keys
keys = {}

def generate_key(key_type: str, key_size: int):
    if key_type.upper() != "AES" or key_size not in [128, 192, 256]:
        raise HTTPException(status_code=400, detail="Invalid key type or size")
    key = uuid.uuid4().bytes[:key_size // 8]  # Generate random key
    key_id = str(uuid.uuid4())
    keys[key_id] = key
    return key_id, base64.b64encode(key).decode()

from cryptography.hazmat.primitives import padding

def encrypt(key_id: str, plaintext: str, algorithm: str):
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
    key = keys.get(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if algorithm.upper() != "AES":
        raise HTTPException(status_code=400, detail="Unsupported algorithm")

    decoded_data = base64.b64decode(ciphertext)
    iv, ciphertext = decoded_data[:16], decoded_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Proper PKCS7 Unpadding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()


def generate_hash(data: str, algorithm: str):
    if algorithm.upper() not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    hash_func = hashes.SHA256() if algorithm.upper() == "SHA-256" else hashes.SHA512()
    digest = hashlib.new(hash_func.name, data.encode()).digest()
    return base64.b64encode(digest).decode(), algorithm.upper()

def verify_hash(data: str, hash_value: str, algorithm: str):
    generated_hash = generate_hash(data, algorithm)[0]
    is_valid = generated_hash == hash_value
    return is_valid, "Hash matches the data." if is_valid else "Hash mismatch."