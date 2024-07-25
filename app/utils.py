# app/utils.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import time
from memory_profiler import memory_usage
import tracemalloc

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
    
    start_time = time.time()
    tracemalloc.start()
    mem_usage_before = memory_usage()[0]
    
    encrypted_message = cipher.encrypt(padded_message)
    
    mem_usage_after = memory_usage()[0]
    encryption_time = time.time() - start_time
    memory_used = mem_usage_after - mem_usage_before
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    ciphertext_length = len(encrypted_message_b64)
    
    return {
        'encrypted_message': encrypted_message_b64,
        'encryption_time': encryption_time,
        'memory_used': memory_used,
        'ciphertext_length': ciphertext_length,
        'peak_memory': peak / 10**6
    }

def decrypt_message(encrypted_message, algorithm, key, iv):
    key_size = {'AES-128': 16, 'AES-192': 24, 'AES-256': 32}.get(algorithm, 16)
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    if len(key) != key_size:
        raise ValueError(f'Invalid key size for {algorithm}')
    encrypted_message = base64.b64decode(encrypted_message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    start_time = time.time()
    tracemalloc.start()
    mem_usage_before = memory_usage()[0]
    
    decrypted_message = cipher.decrypt(encrypted_message).strip()
    
    mem_usage_after = memory_usage()[0]
    decryption_time = time.time() - start_time
    memory_used = mem_usage_after - mem_usage_before
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return {
        'decrypted_message': decrypted_message.decode('utf-8'),
        'decryption_time': decryption_time,
        'memory_used': memory_used,
        'peak_memory': peak / 10**6
    }

def get_security_level(algorithm):
    security_levels = {
        'AES-128': 'High security level with 128-bit key length, resistant to brute force attacks.',
        'AES-192': 'Very high security level with 192-bit key length, stronger than AES-128.',
        'AES-256': 'Extremely high security level with 256-bit key length, recommended for top security applications.'
    }
    return security_levels.get(algorithm, 'Unknown security level')
