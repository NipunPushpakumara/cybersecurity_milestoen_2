from fastapi import FastAPI, HTTPException, status
import logging
import uuid
import base64
from models import KeyRequest, EncryptRequest, DecryptRequest, HashRequest, VerifyHashRequest
from keys import generate_aes_key, generate_rsa_key, store_key, get_key
from services import encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa, generate_hash, verify_hash

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.post("/generate-key", status_code=status.HTTP_201_CREATED)
def generate_key(request: KeyRequest):
    key_type = request.key_type.upper()
    key_size = request.key_size

    try:
        if key_type == "AES":
            key = generate_aes_key(key_size)
            key_id = str(uuid.uuid4())
            store_key(key_id, {"key": key, "type": "AES"})
            return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}

        elif key_type == "RSA":
            key_pair = generate_rsa_key(key_size)
            key_id = str(uuid.uuid4())
            store_key(key_id, {**key_pair, "type": "RSA"})
            return {
                "key_id": key_id,
                "private_key": base64.b64encode(key_pair["private_key"]).decode(),
                "public_key": base64.b64encode(key_pair["public_key"]).decode()
            }

        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid key type")

    except Exception as e:
        logger.error(f"Error generating key: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key generation failed")

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    key_id = request.key_id
    algorithm = request.algorithm.upper()
    plaintext = request.plaintext

    key = get_key(key_id)
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    try:
        if algorithm == "AES":
            if key["type"] != "AES":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Key type mismatch")
            ciphertext = encrypt_aes(key["key"], plaintext)
            return {"ciphertext": ciphertext}

        elif algorithm == "RSA":
            if key["type"] != "RSA":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Key type mismatch")
            ciphertext = encrypt_rsa(key["public_key"], plaintext)
            return {"ciphertext": ciphertext}

        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported algorithm")

    except Exception as e:
        logger.error(f"Error during encryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption failed")

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    key_id = request.key_id
    algorithm = request.algorithm.upper()
    ciphertext = request.ciphertext

    key = get_key(key_id)
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    try:
        if algorithm == "AES":
            if key["type"] != "AES":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Key type mismatch")
            plaintext = decrypt_aes(key["key"], ciphertext)
            return {"plaintext": plaintext}

        elif algorithm == "RSA":
            if key["type"] != "RSA":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Key type mismatch")
            plaintext = decrypt_rsa(key["private_key"], ciphertext)
            return {"plaintext": plaintext}

        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported algorithm")

    except Exception as e:
        logger.error(f"Error during decryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decryption failed")

@app.post("/generate-hash")
def generate_hash_endpoint(request: HashRequest):
    try:
        hash_value = generate_hash(request.data, request.algorithm)
        return {"hash_value": hash_value, "algorithm": request.algorithm}

    except Exception as e:
        logger.error(f"Error generating hash: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Hash generation failed")

@app.post("/verify-hash")
def verify_hash_endpoint(request: VerifyHashRequest):
    try:
        is_valid = verify_hash(request.data, request.hash_value, request.algorithm)
        return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash mismatch."}

    except Exception as e:
        logger.error(f"Error verifying hash: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Hash verification failed")