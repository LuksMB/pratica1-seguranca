import socket, os
from dotenv import load_dotenv
from AuxiliarFunctions import load_private_key_bytes, hex_to_decimal, generate_dh_keypair, create_signed_message, read_signed_message, download_github_public_keys, verify_signature, derive_keys_aes_hmac

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
            b, B = generate_dh_keypair(DH_G, DH_P)
            private_key_bytes = load_private_key_bytes(ENV_PRIVATE_KEY)
            signed_message = create_signed_message(B, private_key_bytes, GITHUB_USERNAME, salt)
            conn.sendall(signed_message)
            DH_SECRET_KEY = pow(client_dh_public_key, b, DH_P)
            key_aes, key_hmac = derive_keys_aes_hmac(DH_SECRET_KEY.to_bytes(2048, byteorder="big"), salt)
            print(f"AES Key: {key_aes.hex()}")
            print(f"HMAC Key: {key_hmac.hex()}")
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
