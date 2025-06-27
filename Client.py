import socket

HOST = 'localhost'  # Endereço IP do servidor (localhost)
PORT = 5320        # Porta usada pelo servidor

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    client_socket.sendall('Olá, servidor!'.encode('utf-8'))
    data = client_socket.recv(1024)

print(f"Resposta do servidor: {data.decode()}")