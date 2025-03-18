from pydantic import BaseModel

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