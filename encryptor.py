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

# Ask user if they have a password
print("Do you have a password based key? (yes/no)")
choice = input("> ").strip().lower()

if choice == "yes":
    password = input("Enter your password:\n> ").strip()
else:
    password = Fernet.generate_key().decode()
    print(f"Your new password (SAVE THIS): {password}")

# Key for Fernet + XOR
key = generate_key_from_password(password)

print("Encrypt or decrypt? (e/d)")
mode = input("> ").strip().lower()

if mode == "e":
    plaintext = input("Enter text to encrypt:\n> ")
    encrypted = fernet_encrypt(plaintext, key)
    xor_encrypted = xor_encrypt(encrypted, key)
    print("Encrypted output (XOR applied):")
    print(xor_encrypted)

elif mode == "d":
    xor_input = input("Enter your encrypted hex:\n> ")
    try:
        decrypted_fernet = xor_decrypt(xor_input, key)
        decrypted_text = fernet_decrypt(decrypted_fernet, key)
        print("Decrypted output:")
        print(decrypted_text)
    except Exception:
        print("Decryption failed. Wrong key and/or corrupted data.")

else:
    print("Invalid command.")
