from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])


def derive_aes_key(shared_secret):
    hash = SHA256.new(data=shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big'))
    return hash.digest()


def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes


def aes_decrypt(data, key):
    iv = data[:AES.block_size]
    ct = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt


def mppe_encrypt_40(data, key):
    session_key = key[:5]
    cipher = ARC4.new(session_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def mppe_encrypt_56(data, key):
    session_key = key[:7]
    cipher = ARC4.new(session_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def mppe_encrypt_128(data, key):
    session_key = key[:16]
    cipher = ARC4.new(session_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def mppe_decrypt_40(data, key):
    session_key = key[:5]  # 5 bytes for 40-bit key
    cipher = ARC4.new(session_key)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def mppe_decrypt_56(data, key):
    session_key = key[:7]  # 7 bytes for 56-bit key
    cipher = ARC4.new(session_key)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def mppe_decrypt_128(data, key):
    session_key = key[:16]  # 16 bytes for 128-bit key
    cipher = ARC4.new(session_key)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data