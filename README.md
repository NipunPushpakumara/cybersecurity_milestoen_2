# Cybersecurity Milestone 2

This repository contains an API that demonstrates basic encryption, decryption, and hashing functionality for educational purposes. It supports AES encryption, decryption, and SHA-256 hashing.

## API Endpoints

### 1. **Generate Key**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `/generate-key`

**Method**: `POST`

**Request Example**:
```bash
curl -X POST "https://cybersecurity-milestoen-2.onrender.com/generate-key" -H "Content-Type: application/json" -d "{\"key_type\":\"AES\", \"key_size\":256}"
