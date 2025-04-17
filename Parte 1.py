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

# Menu interativo
def menu():
    while True:
        print("\nMenu Interativo - Sistema Criptográfico")
        print("1. Gerar chaves RSA")
        print("2. Codificar mensagem com OAEP")
        print("3. Exemplos")
        print("4. Sair")

        escolha = input("Escolha uma opção: ")

        if escolha == "1":
            bits = int(input("Digite o número de bits para as chaves RSA (exemplo: 1024): "))
            keys = generate_rsa_keys(bits)
            print("\nChave Pública:", keys["public_key"])
            print("Chave Privada:", keys["private_key"])
        elif escolha == "2":
            mensagem = input("Digite a mensagem para codificar: ").encode()
            tamanho_chave = int(input("Digite o tamanho da chave pública em bits: "))
            try:
                mensagem_codificada = oaep_encode(mensagem, tamanho_chave)
                print("\nMensagem codificada:", mensagem_codificada)
            except ValueError as e:
                print("Erro:", e)
                print("Dica: Tente usar uma mensagem menor ou uma chave maior.")
        elif escolha == "3":
            print("\nExemplo de Geração de Chaves RSA:")
            keys = generate_rsa_keys(512)
            print("Chave Pública:", keys["public_key"])
            print("Chave Privada:", keys["private_key"])

            print("\nExemplo de Codificação OAEP:")
            mensagem_exemplo = b"Hi"
            tamanho_chave_exemplo = keys["public_key"][1]
            try:
                mensagem_codificada = oaep_encode(mensagem_exemplo, tamanho_chave_exemplo)
                print("Mensagem original:", mensagem_exemplo)
                print("Mensagem codificada:", mensagem_codificada)
            except ValueError as e:
                print("Erro:", e)
        elif escolha == "4":
            print("Saindo do programa. Até mais!")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    menu()
