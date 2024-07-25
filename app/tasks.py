# app/tasks.py
from flask import current_app as app
from app.utils import encrypt_message, decrypt_message

@app.celery.task
def encrypt_message_task(message, algorithm, key, iv):
    return encrypt_message(message, algorithm, key, iv)

@app.celery.task
def decrypt_message_task(encrypted_message, algorithm, key, iv):
    return decrypt_message(encrypted_message, algorithm, key, iv)
