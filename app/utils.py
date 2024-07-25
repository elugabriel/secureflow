from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key_and_iv(algorithm):
    key_size = {'AES-128': 16, 'AES-192': 24, 'AES-256': 32}.get(algorithm, 16)
    key = get_random_bytes(key_size)
    iv = get_random_bytes(AES.block_size)
    return base64.b64encode(key).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

def encrypt_message(message, algorithm, key, iv):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = message.encode('utf-8')
    padded_message = message + b' ' * (AES.block_size - len(message) % AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, algorithm, key, iv):
    key_size = {'AES-128': 16, 'AES-192': 24, 'AES-256': 32}.get(algorithm, 16)
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    if len(key) != key_size:
        raise ValueError(f'Invalid key size for {algorithm}')
    encrypted_message = base64.b64decode(encrypted_message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message).strip()
    return decrypted_message.decode('utf-8')
