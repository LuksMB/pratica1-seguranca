import socket, secrets, os
from dotenv import load_dotenv
from nacl.signing import SigningKey as sk
from cryptography.hazmat.primitives import serialization
from AuxiliarFunctions import load_private_key_bytes, hex_to_decimal, generate_dh_keypair, create_signed_message, read_signed_message, baixar_chaves_publicas_github, verificar_assinatura

# Nessa primeira etapa, vamos importar as bibliotecas necessárias e carregar as variáveis de ambiente do arquivo .env.
# Carregando as variáveis de ambiente do arquivo .env
load_dotenv()

# Definindo constantes
HOST = 'localhost'
PORT = 5320
GITHUB_USERNAME = 'lucasbraga-jit'  # Substitua pelo nome de usuário do GitHub do servidor
ENV_PRIVATE_KEY = os.getenv("PRIVATE_KEY_SERVER").encode("utf-8")  # Obtendo a chave privada Ed25519 do arquivo .env e convertendo para bytes
DH_P_HEX = os.getenv("DH_P_HEX")  # Obtendo o valor de P em hexadecimal do arquivo .env

# Definindo os parâmetros públicos para o Diffie-Hellman usando de exemplo o grupo 2048-bit MODP do RFC 3526
DH_P = hex_to_decimal(DH_P_HEX)  # Convertendo P para decimal
DH_G = 2  # Gerador

# Função para lidar com a conexão do cliente - Código principal do servidor
def handle_client(conn, addr):
    print("\n---------------------------------\n")
    print(f"Conectado por {addr}")
    with conn:
        while True:
            dh_handshake_data = conn.recv(2048)
            if not dh_handshake_data:
                break
            client_dh_public_key, signature, client_username = read_signed_message(dh_handshake_data)

            chaves = baixar_chaves_publicas_github(client_username)
            if not chaves:
                print(f"Não foi possível baixar as chaves públicas do GitHub para o usuário {client_username} ou o mesmo não possui chaves.")
                break

            if verificar_assinatura(chaves, client_dh_public_key, signature, client_username):
                print(f"Assinatura verificada com sucesso para o usuário {client_username}.")
            else:
                print(f"Assinatura inválida para o usuário {client_username}.")
                break

            # Após a verificação da assinatura, é hora de gerar o par de chaves (b, B = g^b mod p) do servidor
            b, B = generate_dh_keypair(DH_G, DH_P) # Gerando o par de chaves do servidor
            
            # A seguir, será feita a assinatura EdRSA da chave pública A do cliente e do seu nome de usuário.
            private_key_bytes = load_private_key_bytes(ENV_PRIVATE_KEY) # Carrega a chave privada a partir do arquivo .env em bytes
            signed_message = create_signed_message(B, private_key_bytes, GITHUB_USERNAME) # Cria a mensagem assinada com a chave privada Ed25519

            conn.sendall(signed_message)

            # Calculando a chave secreta compartilhada (S = A^b mod p)
            DH_SECRET_KEY = pow(client_dh_public_key, b, DH_P) 
            print(f"Chave secreta compartilhada calculada com sucesso: {DH_SECRET_KEY}")

            # dh_handshake_data = conn.recv(2048)
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
            print("\n---------------------------------\n")
            print(f"Servidor ouvindo em {HOST}:{PORT}...")
    except KeyboardInterrupt:
        print("\nServidor encerrado manualmente.")
