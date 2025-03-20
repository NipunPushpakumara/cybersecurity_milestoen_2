# Cybersecurity Milestone 2

This repository contains an API that demonstrates basic key generation, encryption, decryption, and hashing functionality for educational purposes. It supports AES encryption, decryption, and SHA-256 hashing.
## 🚀 Deployment on Render  

This API is deployed on **Render's free Hobby plan**, which comes with the following behavior:  

- 🕒 **Instance sleeps after 15 minutes of inactivity.**  
- 🚦 **Service stops running to free up server resources.**  
- 🔄 **When a new request arrives, Render restarts the instance (cold start).**  
- ⏳ **Cold starts can take a few seconds to a minute.**  

For continuous availability, consider upgrading to a paid plan or using a pinging service like **UptimeRobot**.  
## API Endpoints

### 1. **Generate Key**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `https://cybersecurity-milestoen-2.onrender.com/docs#/generate-key`

**Method**: `POST`

**Request Example**:
```bash
curl -X POST "https://cybersecurity-milestoen-2.onrender.com/generate-key" -H "Content-Type: application/json" -d "{\"key_type\":\"AES\", \"key_size\":256}"
```

### 2. **Encrypt**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `https://cybersecurity-milestoen-2.onrender.com/docs#/encrypt`

**Method**: `POST`

**Request Example**:
```bash

curl -X POST "https://cybersecurity-milestoen-2.onrender.com/encrypt" -H "Content-Type: application/json" -d "{ \"key_id\": \"b765d355-aca4-4710-9118-1a061f2eb5be\", \"plaintext\": \"message-to-encrypt\", \"algorithm\": \"AES\" }"
```

### 3. **Decrypt**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `https://cybersecurity-milestoen-2.onrender.com/docs#/decrypt`

**Method**: `POST`

**Request Example**:
```bash

curl -X POST "https://cybersecurity-milestoen-2.onrender.com/decrypt" -H "Content-Type: application/json" -d "{\"key_id\": \"b765d355-aca4-4710-9118-1a061f2eb5be\", \"ciphertext\": \"dScA5/f0QWWXlC1YqfAcfHVfjHI5WvLjk96sGuJu2BErhyptj0hEFRLz/pnG1LVV\", \"algorithm\": \"AES\"}"
```

### 4. **Generate Hash**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `https://cybersecurity-milestoen-2.onrender.com/docs#/generate-hash`

**Method**: `POST`

**Request Example**:
```bash

curl -X POST "https://cybersecurity-milestoen-2.onrender.com/generate-hash" -H "Content-Type: application/json" -d "{\"data\":\"message_to_hash\", \"algorithm\":\"SHA-256\"}"
```

### 4. **Verify Hash**

This endpoint generates an AES key of the specified size (in this case, 256 bits).

**URL**: `https://cybersecurity-milestoen-2.onrender.com/docs#/verify-hash`

**Method**: `POST`

**Request Example**:
```bash

curl -X POST "https://cybersecurity-milestoen-2.onrender.com/verify-hash" -H "Content-Type: application/json" -d "{\"data\":\"message_to_hash\", \"hash_value\":\"E4Ug7KAGSuMTazmcDxD/GZ5mBoLPqFvJ/ULuD/ioPpE=\",\"algorithm\":\"SHA-256\"}"
```



