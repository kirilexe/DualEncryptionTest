from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key_from_password(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def xor_encrypt(data: str, key: bytes) -> str:
    result = []
    for i, char in enumerate(data):
        key_byte = key[i % len(key)]
        result.append(f"{ord(char) ^ key_byte:02x}")
    return ''.join(result)

def xor_decrypt(encrypted_hex: str, key: bytes) -> str:
    result = []
    for i in range(0, len(encrypted_hex), 2):
        byte = int(encrypted_hex[i:i+2], 16)
        key_byte = key[(i // 2) % len(key)]
        result.append(chr(byte ^ key_byte))
    return ''.join(result)

def fernet_encrypt(text: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def fernet_decrypt(token: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()