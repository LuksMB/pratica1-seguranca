import socket, os
from dotenv import load_dotenv
from AuxiliarFunctions import load_private_key_bytes, hex_to_decimal, generate_dh_keypair, create_signed_message, read_signed_message, download_github_public_keys, verify_signature, derive_keys_aes_hmac

# Carregando as variáveis de ambiente do arquivo .env
load_dotenv()

# Definindo constantes
HOST = 'localhost'  # Endereço IP do servidor (localhost)
PORT = 5320        # Porta usada pelo servidor
GITHUB_USERNAME = 'LuksMB'  # Substitua pelo seu nome de usuário do GitHub
ENV_PRIVATE_KEY = os.getenv("PRIVATE_KEY_CLIENT").encode("utf-8")  # Obtendo a chave privada Ed25519 do arquivo .env e convertendo para bytes
DH_P_HEX = os.getenv("DH_P_HEX")  # Obtendo o valor de P em hexadecimal do arquivo .env

# Definindo os parâmetros públicos para o Diffie-Hellman usando de exemplo o grupo 2048-bit MODP do RFC 3526
DH_P = hex_to_decimal(DH_P_HEX) # Número primo P convertido de hexadecimal para decimal
DH_G = 2  # Gerador

# Após a definição dos parâmetros, é hora de gerar o par de chaves (a, A = g^a mod p) do cliente
a, A = generate_dh_keypair(DH_G, DH_P)

# Gera um salt aleatório para a derivação de chave posterior
salt = os.urandom(16)

# Gera um vetor de inicialização (IV) aleatório para o modo CBC do AES
iv_cbc = os.urandom(16)

# A seguir, será feita a assinatura EdRSA da chave pública A do cliente e do seu nome de usuário.
private_key_bytes = load_private_key_bytes(ENV_PRIVATE_KEY) # Carrega a chave privada a partir do arquivo .env em bytes
signed_message = create_signed_message(A, private_key_bytes, GITHUB_USERNAME, salt) # Cria a mensagem assinada com a chave privada Ed25519

# Criando um socket TCP/IP - Cliente conectando ao servidor
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(signed_message)  # Envia a mensagem assinada com a chave pública A do cliente e o nome de usuário para o servidor
        dh_handshake_data = client_socket.recv(2048)  # Recebe a mensagem assinada do servidor contendo a chave pública B do servidor e o nome de usuário

        server_dh_public_key, signature, server_username, _ = read_signed_message(dh_handshake_data)  # Lê a mensagem assinada recebida do servidor, extraindo a chave pública Diffie-Hellman do servidor

        # Baixa as chaves públicas do GitHub do usuário do servidor
        chaves = download_github_public_keys(server_username)
        if not chaves:
            print(f"Não foi possível baixar as chaves públicas do GitHub para o usuário {server_username} ou o mesmo não possui chaves.")
            raise ValueError(f"Não foi possível baixar as chaves públicas do GitHub para o usuário {server_username} ou o mesmo não possui chaves.")
        
        # Verifica a assinatura usando as chaves públicas baixadas do GitHub
        if verify_signature(chaves, server_dh_public_key, signature, server_username):
            print(f"Assinatura verificada com sucesso para o usuário {server_username}.")
        else:
            print(f"Assinatura inválida para o usuário {server_username}.")
            raise ValueError(f"Assinatura inválida para o usuário {server_username}.")

        # Após a verificação da assinatura, é hora de calcular a chave secreta compartilhada (S = B^a mod p)
        DH_SECRET_KEY = pow(server_dh_public_key, a, DH_P)

        # Derivando as chaves AES e HMAC
        key_aes, key_hmac = derive_keys_aes_hmac(DH_SECRET_KEY.to_bytes(2048, byteorder="big"), salt)
        print(f"AES Key: {key_aes.hex()}")
        print(f"HMAC Key: {key_hmac.hex()}")

        # Mensagem clara para ser cifrada
        mensagem_clara = "Eu contei uma piada sobre construção... mas ainda estou trabalhando no final!"

except Exception as e:
    print(f"Ocorreu um erro durante a comunicação com o servidor: {e}")
