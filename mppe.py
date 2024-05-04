from Crypto.Util import number

def generate_mppe_key_40():
    key = number.getRandomNBitInteger(40).to_bytes(5, 'big')
    return key

def generate_mppe_key_56():
    key = number.getRandomNBitInteger(56).to_bytes(7, 'big')
    return key

def generate_mppe_key_128():
    key = number.getRandomNBitInteger(128).to_bytes(16, 'big')
    return key

generate_mppe_key_40()
generate_mppe_key_56()
generate_mppe_key_128()