import socket, os
from dotenv import load_dotenv
from AuxiliarFunctions import load_private_key_bytes, hex_to_decimal, generate_dh_keypair, create_signed_message

# Carregando as variáveis de ambiente do arquivo .env
load_dotenv()

# Definindo constantes
HOST = 'localhost'  # Endereço IP do servidor (localhost)
PORT = 5320        # Porta usada pelo servidor
GITHUB_USERNAME = 'LuksMB'  # Substitua pelo seu nome de usuário do GitHub
ENV_PRIVATE_KEY = os.getenv("PRIVATE_KEY_CLIENT").encode("utf-8")  # Obtendo a chave privada Ed25519 do arquivo .env e convertendo para bytes

# Definindo os parâmetros públicos para o Diffie-Hellman usando de exemplo o grupo 2048-bit MODP do RFC 3526
P_TEMP_HEX = os.getenv("DH_P_HEX")  # Obtendo o valor de P em hexadecimal do arquivo .env
DH_P = hex_to_decimal(P_TEMP_HEX) # Número primo P convertido de hexadecimal para decimal
DH_G = 2  # Gerador

# Após a definição dos parâmetros, é hora de gerar o par de chaves (a, A = g^a mod p) do cliente
a, A = generate_dh_keypair(DH_G, DH_P)

# A seguir, será feita a assinatura EdRSA da chave pública A do cliente e do seu nome de usuário.
private_key_bytes = load_private_key_bytes(ENV_PRIVATE_KEY) # Carrega a chave privada a partir do arquivo .env em bytes
signed_message = create_signed_message(private_key_bytes, GITHUB_USERNAME, A) # Cria a mensagem assinada com a chave privada Ed25519

# Criando um socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    client_socket.sendall(signed_message)
    data = client_socket.recv(2048)

print(f"Resposta do servidor: '{data.decode()}'")