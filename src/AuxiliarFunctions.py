import secrets, requests
from nacl.signing import SigningKey as sk
from cryptography.hazmat.primitives import serialization

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
    hex_string = hex_string.replace(" ", "")
    return int(hex_string, 16)

# Função para gerar o par de chaves Diffie-Hellman (chave privada e chave pública)
def generate_dh_keypair(g, p):
    private_key = secrets.randbelow(p - 2) + 2  # Chave privada aleatória entre 2 e p-2
    public_key = pow(g, private_key, p)         # Chave pública (g^private_key mod p)
    return private_key, public_key

# Função para criar uma mensagem assinada com a chave privada Ed25519
def create_signed_message(bytes_key, username, public_key):
    private_key = sk(bytes_key) # Carrega a chave privada Ed25519 a partir dos bytes
    message = f"{public_key}:{username}".encode("utf-8") # Cria a mensagem a ser assinada
    signed = private_key.sign(message) # Assina a mensagem com a chave privada
    signed_message = f"{public_key}:{signed.signature.hex()}:{username}".encode("utf-8") # Formata a mensagem assinada como uma string codificada em bytes
    return signed_message

# Função auxiliar para baixar as chaves públicas do GitHub de um usuário
def baixar_chaves_publicas_github(username):
    url = f"https://github.com/{username}.keys"
    response = requests.get(url)

    # Verifica se a requisição foi bem-sucedida
    if response.status_code != 200:
        raise requests.HTTPError(f"Erro ao buscar chaves: {response.status_code}")
    
    # Divide por linhas e remove vazios
    chaves = [linha.strip() for linha in response.text.strip().split("\n") if linha.strip()]
    return chaves