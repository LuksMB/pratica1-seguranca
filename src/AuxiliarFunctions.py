import secrets, requests
from nacl.signing import SigningKey as sk
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time

# Função auxiliar para carregar a chave privada openssh e convertê-la para bytes
def load_private_key_bytes(key):
    private_key = serialization.load_ssh_private_key(
        key,
        password=None   # ou a senha, se for protegida
    )

    # Convertendo a chave privada para 32 bytes no formato Raw para uso posterior com SigningKey
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_bytes

# Função auxiliar feita para converter para decimal o hexadecimal de P
# É necessário remover todos os espaços e interpretar a string resultante como um número hexadecimal.
def hex_to_decimal(hex_string):
    return int(hex_string, 16)

# Função para gerar o par de chaves Diffie-Hellman (chave privada e chave pública)
def generate_dh_keypair(g, p):
    private_key = secrets.randbelow(p - 2) + 2  # Chave privada aleatória entre 2 e p-2
    public_key = pow(g, private_key, p)         # Chave pública (g^private_key mod p)
    return private_key, public_key

# Função para criar uma mensagem assinada com a chave privada Ed25519
def create_signed_message(dh_public_key, bytes_key, username, salt):
    private_key = sk(bytes_key) # Carrega a chave privada Ed25519 a partir dos bytes
    message = f"{dh_public_key}:{username}".encode("utf-8") # Cria a mensagem a ser assinada
    signed = private_key.sign(message) # Assina a mensagem com a chave privada
    signed_message = f"{dh_public_key}:{signed.signature.hex()}:{username}:{salt.hex()}".encode("utf-8") # Formata a mensagem assinada como uma string codificada em bytes
    return signed_message

def read_signed_message(signed_message):
    # Divide a mensagem assinada em partes
    parts = signed_message.decode("utf-8").split(":")

    if len(parts) != 4:
        raise ValueError("Mensagem assinada inválida.")

    dh_public_key = int(parts[0])  # Chave pública Diffie-Hellman como inteiro
    signature = bytes.fromhex(parts[1])  # Assinatura em formato hexadecimal
    username = parts[2]  # Nome de usuário
    salt = bytes.fromhex(parts[3])  # Salt

    return dh_public_key, signature, username, salt

# Função auxiliar para baixar as chaves públicas do GitHub de um usuário
def download_github_public_keys(username, retries=3, delay=2):
    url = f"https://github.com/{username}.keys"
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                chaves = [linha.strip() for linha in response.text.strip().split("\n") if linha.strip()]
                return chaves
            else:
                raise requests.HTTPError(f"Erro ao buscar chaves para o usuário {username}. Status: {response.status_code}")
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise requests.HTTPError(f"Erro ao buscar chaves para o usuário {username}.")

# Função auxiliar para verificar a assinatura usando as chaves públicas
def verify_signature(chaves, dh_public_key, signature, username):
    for chave in chaves:
        try:
            public_key = serialization.load_ssh_public_key(chave.encode("utf-8"))
            public_key.verify(signature, f"{dh_public_key}:{username}".encode("utf-8"))
            return True
        except Exception:
            continue  # Se a verificação falhar, tenta com a próxima chave
    return False

# Função auxiliar para derivar uma chave secreta usando PBKDF2
def derive_keys_aes_hmac(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=500000,
    )
    # Deriva a chave usando PBKDF2
    # A chave derivada será de 64 bytes, dividida em duas partes:
    derived_key = kdf.derive(password)

    # Separar as chaves
    key_aes = derived_key[:32]
    key_hmac = derived_key[32:]
    return key_aes, key_hmac