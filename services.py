import base64
import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException, status

def encrypt_aes(key: bytes, plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext.encode(), 16)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes(key: bytes, ciphertext: str) -> str:
    decoded_data = base64.b64decode(ciphertext)
    iv, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_plaintext, 16).decode()

def encrypt_rsa(public_key: bytes, plaintext: str) -> str:
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_rsa(private_key: bytes, ciphertext: str) -> str:
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    decoded_ciphertext = base64.b64decode(ciphertext)
    plaintext = cipher.decrypt(decoded_ciphertext)
    return plaintext.decode()

def generate_hash(data: str, algorithm: str) -> str:
    if algorithm not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported algorithm")
    hash_func = hashlib.sha256 if algorithm == "SHA-256" else hashlib.sha512
    digest = hash_func(data.encode()).digest()
    return base64.b64encode(digest).decode()

def verify_hash(data: str, hash_value: str, algorithm: str) -> bool:
    generated_hash = generate_hash(data, algorithm)
    return generated_hash == hash_value