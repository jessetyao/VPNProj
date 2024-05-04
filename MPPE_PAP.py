import hashlib
import hmac
import os


def derive_keys(username, password):
    username_bytes = username.encode('utf-8')
    password_bytes = password.encode('utf-8')

    salt = os.urandom(16)

    session_key = hmac.new(password_bytes, salt + username_bytes, hashlib.sha256).digest()
    send_key = hmac.new(session_key, b'\x00' * 32, hashlib.sha256).digest()
    recv_key = hmac.new(session_key, b'\x01' * 32, hashlib.sha256).digest()

    return session_key, send_key, recv_key

username = "example_user"
password = "example_password"

session_key, send_key, recv_key = derive_keys(username, password)

print("Session Key:", session_key.hex())
print("Send Key:", send_key.hex())
print("Receive Key:", recv_key.hex())