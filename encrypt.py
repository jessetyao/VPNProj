from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])

def derive_aes_key(shared_secret):
    hash = SHA256.new(data=shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big'))
    return hash.digest()

def aes_encrypt(data, key):
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_decrypt(data, key):
    """Decrypt data using AES."""
    iv = data[:AES.block_size]
    ct = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt