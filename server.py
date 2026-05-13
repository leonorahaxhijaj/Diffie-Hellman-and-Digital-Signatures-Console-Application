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