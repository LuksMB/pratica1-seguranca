import socket, secrets, os
from dotenv import load_dotenv
from nacl.signing import SigningKey as sk
from cryptography.hazmat.primitives import serialization

# Nessa primeira etapa, vamos importar as bibliotecas necessárias e carregar as variáveis de ambiente do arquivo .env.
# Carregando as variáveis de ambiente do arquivo .env
load_dotenv()

# Definindo constantes
HOST = 'localhost'
PORT = 5320
GITHUB_USERNAME = 'lucasbraga-jit'  # Substitua pelo nome de usuário do GitHub do servidor
ENV_KEY = os.getenv("PRIVATE_KEY_SERVER").encode("utf-8")  # Obtendo a chave privada Ed25519 do arquivo .env e convertendo para bytes

# Função para lidar com a conexão do cliente - Código principal do servidor
def handle_client(conn, addr):
    print("\n\n\n---------------------------------\n\n\n")
    print(f"Conectado por {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = data.decode()
            print(f"Recebido do cliente {addr}: {msg}")
            conn.sendall(f"Mensagem recebida: {msg}".encode())
    print(f"Conexão encerrada com {addr}")

# Criando um socket TCP/IP - Servidor e conectando ao cliente
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Servidor ouvindo em {HOST}:{PORT}...")

    try:
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)
            print("\n\n\n---------------------------------\n\n\n")
    except KeyboardInterrupt:
        print("\nServidor encerrado manualmente.")
