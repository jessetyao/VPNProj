def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])

def IKEv2_encrypt(data):
    ...
