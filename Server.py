import socket

HOST = 'localhost'
PORT = 5320

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Servidor ouvindo em {HOST}:{PORT}...")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Conectado por {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = data.decode()
            print(f"Recebido do cliente: {msg}")
            conn.sendall(f"Mensagem recebida: {msg}".encode())