import socket, os
from dotenv import load_dotenv
from AuxiliarFunctions import load_private_key_bytes, hex_to_decimal, generate_dh_keypair, create_signed_message, read_signed_message, download_github_public_keys, verify_signature, derive_keys_aes_hmac, calcular_hmac, decrypt_message

load_dotenv()

HOST = 'localhost'
PORT = 5320
GITHUB_USERNAME = 'lucasbraga-jit'
ENV_PRIVATE_KEY = os.getenv("PRIVATE_KEY_SERVER").encode("utf-8")
DH_P_HEX = os.getenv("DH_P_HEX")
DH_P = hex_to_decimal(DH_P_HEX)
DH_G = 2

def handle_client(conn, addr):
    print("\n---------------------------------\n")
    print(f"Conectado por {addr}")
    with conn:
        while True:
            dh_handshake_data = conn.recv(2048)
            if not dh_handshake_data:
                break
            client_dh_public_key, signature, client_username, salt = read_signed_message(dh_handshake_data)
            chaves = download_github_public_keys(client_username)
            if not chaves:
                print(f"Não foi possível baixar as chaves públicas do GitHub para o usuário {client_username} ou o mesmo não possui chaves.")
                break
            if verify_signature(chaves, client_dh_public_key, signature, client_username):
                print(f"Assinatura verificada com sucesso para o usuário {client_username}.")
            else:
                print(f"Assinatura inválida para o usuário {client_username}.")
                break

            b, B = generate_dh_keypair(DH_G, DH_P)  # Chave privada e pública do servidor
            private_key_bytes = load_private_key_bytes(ENV_PRIVATE_KEY) # Carrega a chave privada do servidor
            signed_message = create_signed_message(B, private_key_bytes, GITHUB_USERNAME, salt) # Cria a mensagem assinada com a chave privada Ed25519 do servidor
            conn.sendall(signed_message) # Envia a mensagem assinada com a chave pública B do servidor e o nome de usuário para o cliente
            DH_SECRET_KEY = pow(client_dh_public_key, b, DH_P) # Calcula a chave secreta compartilhada (S = A^b mod p)
            key_aes, key_hmac = derive_keys_aes_hmac(DH_SECRET_KEY.to_bytes(2048, byteorder="big"), salt) # Deriva as chaves AES e HMAC

            # Recebe o pacote do cliente (hmac_tag + iv_aes + mensagem_cifrada)
            pacote = conn.recv(2048)
            if not pacote:
                break

            if len(pacote) < 32:
                print("Pacote recebido é menor que 32 bytes, conexão encerrada.")
                break

            hmac_tag = pacote[:32]
            iv_aes = pacote[32:48]
            mensagem_cifrada = pacote[48:]

            # Verifica o HMAC da mensagem recebida
            hmac_calculado = calcular_hmac(key_hmac, iv_aes, mensagem_cifrada)
            if hmac_calculado != hmac_tag:
                print("HMAC inválido, conexão encerrada.")
                break

            # Descriptografa a mensagem recebida
            mensagem_clara = decrypt_message(mensagem_cifrada, key_aes, iv_aes)
            print(f"Mensagem recebida do cliente {client_username}: {mensagem_clara}")
            confirmacao = "Mensagem recebida com sucesso!"

            conn.sendall(confirmacao.encode("utf-8"))  # Envia uma resposta ao cliente

    print(f"Conexão encerrada com {addr}")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        server_socket.settimeout(1.0)  # Timeout de 1 segundo
        print(f"Servidor ouvindo em {HOST}:{PORT}...")
        while True:
            try:
                conn, addr = server_socket.accept()
                try:
                    handle_client(conn, addr)
                except Exception as e:
                    print(f"Erro ao lidar com o cliente {addr}: {e}")
                finally:
                    conn.close()
                print("\n---------------------------------\n")
                print(f"Servidor ouvindo em {HOST}:{PORT}...")
            except socket.timeout:
                continue
except KeyboardInterrupt:
    print("\nServidor encerrado manualmente.")
