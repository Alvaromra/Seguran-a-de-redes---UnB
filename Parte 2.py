import random
from hashlib import sha256

# Função para verificar se um número é primo (teste de Miller-Rabin)
def is_prime(n, k=10):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Escreve n-1 como 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Teste de Miller-Rabin
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Função para gerar números primos grandes
def generate_large_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        prime_candidate |= (1 << bits - 1) | 1  # Garante que o número tenha o tamanho certo e seja ímpar
        if is_prime(prime_candidate):
            return prime_candidate

# Geração de chaves RSA
def generate_rsa_keys(bits=1024):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Escolhe e (padrão: 65537)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    # Calcula d (inverso modular de e mod phi)
    d = mod_inverse(e, phi)

    return {
        "public_key": (e, n),
        "private_key": (d, n),
    }

# Função para calcular o máximo divisor comum (GCD)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Função para calcular o inverso modular
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# OAEP Encoding (simplificado para exemplo)
def oaep_encode(message, n):
    hash_length = sha256().digest_size
    padding = n.bit_length() // 8 - len(message) - 2 * hash_length - 2
    if padding < 0:
        raise ValueError("Mensagem muito longa para o tamanho da chave.")

    ps = b"\x00" * padding
    db = sha256(b"label").digest() + ps + b"\x01" + message
    seed = random.randbytes(hash_length)
    db_mask = mgf1(seed, len(db))
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hash_length)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db

# OAEP Decoding (não implementado neste exemplo)

def mgf1(seed, length):
    output = b""
    for counter in range((length + sha256().digest_size - 1) // sha256().digest_size):
        c = counter.to_bytes(4, byteorder="big")
        output += sha256(seed + c).digest()
    return output[:length]

# Funções para a cifração híbrida
def hybrid_encrypt(message, public_key):
    # Geração de chave simétrica manualmente
    symmetric_key = random.getrandbits(128).to_bytes(16, byteorder="big")

    # Cifração da mensagem com AES manual (modo CBC simplificado)
    iv = random.getrandbits(128).to_bytes(16, byteorder="big")
    padded_message = pad_message(message, 16)
    encrypted_message = aes_encrypt(padded_message, symmetric_key, iv)

    # Cifração da chave simétrica com RSA
    e, n = public_key
    encrypted_key = pow(int.from_bytes(symmetric_key, byteorder="big"), e, n)

    return {
        "encrypted_key": encrypted_key,
        "iv": iv,
        "encrypted_message": encrypted_message,
    }

def hybrid_decrypt(encrypted_data, private_key):
    # Decifração da chave simétrica com RSA
    d, n = private_key
    encrypted_key = encrypted_data["encrypted_key"]
    symmetric_key = pow(encrypted_key, d, n).to_bytes(16, byteorder="big")

    # Decifração da mensagem com AES manual (modo CBC simplificado)
    iv = encrypted_data["iv"]
    encrypted_message = encrypted_data["encrypted_message"]
    decrypted_message = aes_decrypt(encrypted_message, symmetric_key, iv)

    return unpad_message(decrypted_message, 16)

# Implementação manual de AES simplificada
def pad_message(message, block_size):
    padding_length = block_size - (len(message) % block_size)
    return message + bytes([padding_length] * padding_length)

def unpad_message(padded_message, block_size):
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]

def aes_encrypt(message, key, iv):
    state = [message[i:i + 16] for i in range(0, len(message), 16)]
    encrypted = b""
    for block in state:
        iv = xor_bytes(block, iv)
        encrypted += iv
    return encrypted

def aes_decrypt(encrypted_message, key, iv):
    state = [encrypted_message[i:i + 16] for i in range(0, len(encrypted_message), 16)]
    decrypted = b""
    for block in state:
        decrypted += xor_bytes(block, iv)
        iv = block
    return decrypted

def xor_bytes(block1, block2):
    return bytes(a ^ b for a, b in zip(block1, block2))

# Exemplo de uso
def main():
    keys = generate_rsa_keys(1024)
    public_key, private_key = keys["public_key"], keys["private_key"]
    print("Chave Pública:", public_key)
    print("Chave Privada:", private_key)

    # Mensagem para cifrar
    message = b"Mensagem secreta!"

    # Cifração híbrida
    encrypted_data = hybrid_encrypt(message, public_key)
    print("Dados Cifrados:", encrypted_data)

    # Decifração híbrida
    decrypted_message = hybrid_decrypt(encrypted_data, private_key)
    print("Mensagem Decifrada:", decrypted_message)

if __name__ == "__main__":
    main()
