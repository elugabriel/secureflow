from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key_and_iv(algorithm):
    if algorithm == 'AES-128':
        key = get_random_bytes(16)
    elif algorithm == 'AES-192':
        key = get_random_bytes(24)
    elif algorithm == 'AES-256':
        key = get_random_bytes(32)
    iv = get_random_bytes(16)
    return base64.b64encode(key).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

def encrypt_message(plain_text, key, iv):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = plain_text + (16 - len(plain_text) % 16) * chr(16 - len(plain_text) % 16)
    encrypted_text = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

def decrypt_message(encrypted_text, key, iv):
    # key = base64.b64decode(key)
    # iv = base64.b64decode(iv)
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypted_padded_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode('utf-8')
    # padding_len = ord(decrypted_padded_text[-1])
    #return decrypted_padded_text[:-padding_len]
    received_messages = Message.query.filter_by(recipient_id=current_user.id).all()
    return render_template('messages.html', messages=received_messages)

