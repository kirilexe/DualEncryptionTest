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

print("Do you have a password based key? (yes/no)")
choice = input("> ").strip().lower()

if choice == "yes":
    password = input("Enter your password:\n> ").strip()
else:
    password = Fernet.generate_key().decode()
    print(f"Your new password (SAVE THIS): {password}")

key = generate_key_from_password(password)

print("Encrypt or decrypt? (e/d)")
mode = input("> ").strip().lower()

if mode == "e":
    choice = input("Do you want to encrypt a text file instead of typing the text? (y/n)\n> ").lower()

    if choice == "y":
        file_name = input("Enter the name of the text file to encrypt (e.g input.txt, make sure it's in the same folder):\n> ")
        output_file = input("Enter the name for the encrypted file (e.g encrypted):\n> ")
        if not output_file.lower().endswith(".txt"):
            output_file += ".txt"

        try:
            with open(file_name, "r", encoding="utf-8") as file:
                plaintext = file.read()

            encrypted = fernet_encrypt(plaintext, key)
            xor_encrypted = xor_encrypt(encrypted, key)

            with open(output_file, "w", encoding="utf-8") as file:
                file.write(xor_encrypted)
                file.flush()

            print(f"Encrypted content saved to {output_file}")
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except Exception as e:
            print(f"An error occurred: {e}")

    else:
        plaintext = input("Enter text to encrypt:\n> ")
        encrypted = fernet_encrypt(plaintext, key)
        xor_encrypted = xor_encrypt(encrypted, key)
        print("Encrypted output (XOR applied):")
        print(xor_encrypted)

elif mode == "d":
    choice = input("Do you want to decrypt a file instead of pasting the encrypted hex? (y/n)\n> ").lower()

    if choice == "y":
        file_name = input("Enter the name of the encrypted file (e.g., encrypted.txt):\n> ")
        output_file = input("Enter the name for the decrypted output file (e.g., output):\n> ")
        if not output_file.lower().endswith(".txt"):
            output_file += ".txt"

        try:
            with open(file_name, "r", encoding="utf-8") as file:
                xor_input = file.read().strip()

            decrypted_fernet = xor_decrypt(xor_input, key)
            decrypted_text = fernet_decrypt(decrypted_fernet, key)

            with open(output_file, "w", encoding="utf-8") as file:
                file.write(decrypted_text)
                file.flush()

            print(f"Decrypted content saved to {output_file}")
        except FileNotFoundError:
            print(f"File '{file_name}' not found.")
        except Exception:
            print("Error - wrong key and/or corrupted data.")

    else:
        xor_input = input("Enter your encrypted hex:\n> ")
        try:
            decrypted_fernet = xor_decrypt(xor_input, key)
            decrypted_text = fernet_decrypt(decrypted_fernet, key)
            print("Decrypted output:")
            print(decrypted_text)
        except Exception:
            print("Error - wrong key and/or corrupted data.")
