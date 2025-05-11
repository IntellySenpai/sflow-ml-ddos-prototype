import os
import socket


# UDP Socket for sflow logs
UDP_IP = "0.0.0.0"
UDP_PORT = 5514
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

# UDP Socket to send preprocessor-2
UDP_IP_PREPROCESSOR_2 = "10.0.1.12"
UDP_PORT_PREPROCESSOR_2 = 5514
socket_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# SQLITE
DB_PATH = os.getenv("DB_PATH")

# External sources Tokens
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY")
