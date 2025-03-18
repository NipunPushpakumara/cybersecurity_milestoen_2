import uuid
import base64

# Dictionary to store keys
keys = {}

def store_key(key_size: int):
    key = uuid.uuid4().bytes[:key_size // 8]
    key_id = str(uuid.uuid4())
    keys[key_id] = key
    return key_id, base64.b64encode(key).decode()

def get_key(key_id: str):
    return keys.get(key_id)