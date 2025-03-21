import os
import uuid
from Crypto.PublicKey import RSA
from fastapi import HTTPException, status

keys = {}  # Dictionary to store keys

def generate_aes_key(key_size: int) -> bytes:
    if key_size not in [128, 192, 256]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid AES key size")
    return os.urandom(key_size // 8)

def generate_rsa_key(key_size: int) -> dict:
    if key_size not in [2048, 4096]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid RSA key size")
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return {"private_key": private_key, "public_key": public_key}

def store_key(key_id: str, key_data: dict):
    keys[key_id] = key_data

def get_key(key_id: str):
    return keys.get(key_id)