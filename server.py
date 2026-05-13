import socket, os, hashlib, warnings

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

warnings.filterwarnings("ignore", category=UserWarning)

# --- RSA Keys for Signatures ---
server_private_rsa = rsa.generate_private_key(65537, 2048)
server_public_rsa = server_private_rsa.public_key()

# --- DH Parameters ---
parameters = dh.generate_parameters(generator=2, key_size=2048)

server_private_dh = parameters.generate_private_key()
server_public_dh = server_private_dh.public_key()

def send_secure(conn, data):
    conn.sendall(len(data).to_bytes(4, 'big') + data)

def recv_secure(conn):
    try:
        raw_len = conn.recv(4)

        if not raw_len:
            return None

        msg_len = int.from_bytes(raw_len, 'big')
        data = b''

        while len(data) < msg_len:
            part = conn.recv(msg_len - len(data))

            if not part:
                return None

            data += part

        return data

    except:
        return None
    
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server:")
    print("Listening for connections...")

    conn, addr = server_socket.accept()
    print("Client connected.")

    # 1. DH Exchange
    print("Performing Diffie-Hellman key exchange...")

    dh_pub_bytes = server_public_dh.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    send_secure(conn, dh_pub_bytes)

    client_dh_bytes = recv_secure(conn)
    client_public_dh = serialization.load_pem_public_key(client_dh_bytes)

    shared_key = server_private_dh.exchange(client_public_dh)

    aes_key = HKDF(
        hashes.SHA256(),
        32,
        None,
        b'handshake'
    ).derive(shared_key)

    # 2. Digital Signature
    rsa_pub_bytes = server_public_rsa.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Shared secret established. Sending signed welcome message...")

    welcome_msg = b"Welcome to the Secure Server!"

    signature = server_private_rsa.sign(
        welcome_msg,
        padding.PSS(
            padding.MGF1(hashes.SHA256()),
            padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    send_secure(conn, rsa_pub_bytes)
    send_secure(conn, welcome_msg)
    send_secure(conn, signature)

    # 3. Chat
    while True:
        data = recv_secure(conn)

        if not data:
            break

        iv, enc_msg = data[:16], data[16:]

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CFB(iv)
        )

        decryptor = cipher.decryptor()
        dec_data = decryptor.update(enc_msg) + decryptor.finalize()

        received_hash = dec_data[:64]
        message = dec_data[64:]

        new_hash = hashlib.sha256(message).hexdigest().encode()

        if received_hash == new_hash:
            print("Integrity OK")
            print(f"Client: {message.decode()}")
        else:
            print("Message modified!")

        reply = input("Server (type 'exit' to quit): ")

        if reply.lower() == 'exit':
            break

        msg_hash = hashlib.sha256(reply.encode()).hexdigest().encode()
        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CFB(iv)
        )

        encryptor = cipher.encryptor()

        enc_payload = (
            iv +
            encryptor.update(msg_hash + reply.encode()) +
            encryptor.finalize()
        )

        send_secure(conn, enc_payload)

        reply_signature = server_private_rsa.sign(
            reply.encode(),
            padding.PSS(
                padding.MGF1(hashes.SHA256()),
                padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        send_secure(conn, reply_signature)

    conn.close()
    server_socket.close()


if __name__ == "__main__":
    start_server()