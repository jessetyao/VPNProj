from Crypto.Util import number

def generate_prime(n):
    return number.getPrime(n)

def get_private_key(prime):
    return number.getRandomRange(2, prime - 1)

def get_public_key(private_key, prime, base):
    return pow(base, private_key, prime)
