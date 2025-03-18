from fastapi import FastAPI, HTTPException
from models import KeyRequest, EncryptRequest, DecryptRequest, HashRequest, VerifyHashRequest
from services import generate_key, encrypt, decrypt, generate_hash, verify_hash

app = FastAPI()

@app.post("/generate-key")
def generate_key_route(request: KeyRequest):
    key_id, key_value = generate_key(request.key_type, request.key_size)
    return {"key_id": key_id, "key_value": key_value}

@app.post("/encrypt")
def encrypt_route(request: EncryptRequest):
    ciphertext = encrypt(request.key_id, request.plaintext, request.algorithm)
    return {"ciphertext": ciphertext}

@app.post("/decrypt")
def decrypt_route(request: DecryptRequest):
    plaintext = decrypt(request.key_id, request.ciphertext, request.algorithm)
    return {"plaintext": plaintext}

@app.post("/generate-hash")
def generate_hash_route(request: HashRequest):
    hash_value, algorithm = generate_hash(request.data, request.algorithm)
    return {"hash_value": hash_value, "algorithm": algorithm}

@app.post("/verify-hash")
def verify_hash_route(request: VerifyHashRequest):
    is_valid, message = verify_hash(request.data, request.hash_value, request.algorithm)
    return {"is_valid": is_valid, "message": message}
