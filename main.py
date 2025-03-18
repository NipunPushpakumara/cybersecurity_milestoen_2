from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import hashlib
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = FastAPI()
keys = {}  # Dictionary to store keys

class KeyRequest(BaseModel):
    key_type: str
    key_size: int

class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str

class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str

@app.post("/generate-key")
def generate_key(request: KeyRequest):
    if request.key_type.upper() != "AES" or request.key_size not in [128, 192, 256]:
        raise HTTPException(status_code=400, detail="Invalid key type or size")
    key = uuid.uuid4().bytes[:request.key_size // 8]  # Generate random key
    key_id = str(uuid.uuid4())
    keys[key_id] = key
    return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    key = keys.get(request.key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if request.algorithm.upper() != "AES":
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    iv = uuid.uuid4().bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = request.plaintext.ljust(16 * ((len(request.plaintext) // 16) + 1))
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return {"ciphertext": base64.b64encode(iv + ciphertext).decode()}

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    key = keys.get(request.key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if request.algorithm.upper() != "AES":
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    decoded_data = base64.b64decode(request.ciphertext)
    iv, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return {"plaintext": plaintext.strip().decode()}

@app.post("/generate-hash")
def generate_hash(request: HashRequest):
    if request.algorithm.upper() not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    hash_func = hashes.SHA256() if request.algorithm.upper() == "SHA-256" else hashes.SHA512()
    digest = hashlib.new(hash_func.name, request.data.encode()).digest()
    return {"hash_value": base64.b64encode(digest).decode(), "algorithm": request.algorithm.upper()}

@app.post("/verify-hash")
def verify_hash(request: VerifyHashRequest):
    generated_hash = generate_hash(HashRequest(data=request.data, algorithm=request.algorithm))["hash_value"]
    is_valid = generated_hash == request.hash_value
    return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash mismatch."}