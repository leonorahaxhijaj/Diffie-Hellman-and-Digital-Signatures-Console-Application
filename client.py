import socket, os, hashlib, warnings
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

warnings.filterwarnings("ignore", category=UserWarning)

def send_secure(sock, data):
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_secure(sock):
    try:
        raw_len = sock.recv(4)
        if not raw_len: return None
        msg_len = int.from_bytes(raw_len, 'big')
        data = b''
        while len(data) < msg_len:
            part = sock.recv(msg_len - len(data))
            data += part
        return data
    except: return None

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Client:")
    print("Connecting to server...")
    client_socket.connect(('localhost', 12345))

    server_dh_bytes = recv_secure(client_socket)
    server_public_dh = serialization.load_pem_public_key(server_dh_bytes)
    client_private_dh = server_public_dh.parameters().generate_private_key()
    send_secure(client_socket, client_private_dh.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    
    aes_key = HKDF(hashes.SHA256(), 32, None, b'handshake').derive(client_private_dh.exchange(server_public_dh))

    server_rsa_pub_bytes = recv_secure(client_socket)
    server_public_rsa = serialization.load_pem_public_key(server_rsa_pub_bytes)
    welcome_msg = recv_secure(client_socket)
    signature = recv_secure(client_socket)

    print("Received public key and signed message from server.")
    print("Verifying server's signature...")

    try:
        server_public_rsa.verify(signature, welcome_msg, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Signature valid. Trusted communication established.")
        print(f"Server says: {welcome_msg.decode()}")
    except:
        print("Signature invalid!")
        return