import secrets
import base64

aes_key = secrets.token_bytes(32)  # 32-byte key
encoded_key = base64.b64encode(aes_key).decode()  

print(encoded_key)  # Copy this value into .env file