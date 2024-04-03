import socket
import hashlib
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# Constants for Diffie-Hellman key exchange
P = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
G = 2

# Initialize Diffie-Hellman parameters and keys that will be used in AES mode CBC
pn = dh.DHParameterNumbers(P, G)
parameters = pn.parameters()
private_key = parameters.generate_private_key()
client_public_key = private_key.public_key()
public = client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)  # Passa a chave publica de DHPublicKey para bytes

# Initialization of a global key variable used in AES mode CBC
key = b''

# Function to hash data using SHA-256
def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode("utf-8"))
    return sha256.hexdigest()

# Function to encrypt with AES in mode CBC
def encrypt_aes(key, plaintext, data_hash, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # Combine plaintext and hash from text
    plaintext_with_hash = plaintext + data_hash
    # The padder applies padding.PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_with_hash.encode("utf-8")) + padder.finalize() # Adds the extra bytes to the message with the hash with padder
    ciphertext = encryptor.update(padded_data) + encryptor.finalize() # Creats the encrypted text with padded information so the message as the right size
    return ciphertext # Returns the encrypted text

# Function to decrypt with AES in mode CBC
def decrypt_aes(key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    # Removes the extra bytes introduced by the padder, leaving only the message and the hash
    # The padder applies padding.PKCS7 but for unpadding
    padder = padding.PKCS7(128).unpadder()
    plaintext_with_hash = padder.update(padded_data) + padder.finalize()# Returns the text and hash without the padding
    plaintext = plaintext_with_hash[:-64]  # Removes the last 64 bytes that represent the hash leaving only the message
    received_hash = plaintext_with_hash[-64:]  # Obtains the last 64 bytes, refering to the hash
    return plaintext.decode("utf-8"), received_hash.decode("utf-8") # Returns the hash and the plaintext decoded

# Generator of private key using RSA
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Obtain the corresponding public key
    public_key = private_key.public_key()
    # Returns both the private key and the public key
    return private_key, public_key

# Serialization of the public key in PEM FORMAT
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Function that signs the message with the private key using RSA 
def sign_message(message, private_key):
    #Imports the asymmetric padding from cryptography inside the function to prevent it from using the other padding(was causing a conflict in the code)
    from cryptography.hazmat.primitives.asymmetric import padding
    #To sign the message the message is needed
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
# Function that verifies the signature using the public key from the other side, generated with RSA
def verify_signature(message, signature, public_key):
    #Imports the asymmetric padding from cryptography inside the function to prevent it from using the other padding(was causing a conflict in the code)
    from cryptography.hazmat.primitives.asymmetric import padding
    #To verify is needed the signature received and the message received aswell
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
# Function that encrypts the message using the public key from the other side, generated with RSA
def encrypt_message(message, public_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    # Encrypt the message using OAEP padding with SHA-256
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message
# Function that decrypts the message using the private key generated with RSA
def decrypt_message(encrypted_message, private_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    # Decrypt the message using OAEP padding with SHA-256
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message
# Handler to send messages in mode a 
def handle_send_data_a(client_socket):
    while True:
        # Reads the message from the terminal
        data = input("Enter data: ")
        if data == 'exit':
            client_socket.close()
        # Calculate the hash of the data
        data_hash = hash_data(data)
        # Concatenate the data and its hash
        combined_data = data + data_hash
        # Send the combined data to the server
        client_socket.send(combined_data.encode("utf-8"))

# Handler to receive messages in mode a 
def handle_receive_data_a(client_socket):
    while True:
        # Receives the message from the other side
        combined_data = client_socket.recv(1024).decode("utf-8")
        # Extract the data and its hash based on the known hash size
        data = combined_data[:-64] 
        received_hash = combined_data[-64:]
        # Calculate the hash of the received data
        calculated_hash = hash_data(data)
        # Verifies the integrity of the message by comparing the received hash with calculated hash
        if received_hash == calculated_hash:
            print(f"Received data: {data}")
            print("Integrity check: Passed")
        else:
            print(f"Received data: {data}")
            print("Integrity check: Failed")

# Handler to send messages in mode b
def handle_send_data_b(client_socket,key,iv_b):
        while True:
            # Reads the message from the terminal    
            data = input("Enter data: ")
            if data == 'exit':
                client_socket.close()
            # Calculates the hash of the input
            data_hash = hash_data(data)
            # Encrypt the data using the provided 'encrypt' function
            ciphertext = encrypt_aes(key, data, data_hash, iv_b)
            # Sends the encrypted message
            client_socket.send(ciphertext)

# Handler to receive messages in mode b
def handle_receive_data_b(client_socket,key,iv_b):   
    while True:
        # Receives the message
        ciphertext = client_socket.recv(1024)
        # Decrypts the message using decrypt_aes
        plaintext, received_hash = decrypt_aes(key, ciphertext, iv_b)
        # Calculates the expect hash for a certain message
        expected_hash = hash_data(plaintext)
        #  Verifies the integrity of the message by comparing the received hash with calculated hash
        if expected_hash == received_hash:
            print(f"Received data: {plaintext}")
            print("Integrity check: Passed")
        else:
            print(f"Received data: {plaintext}")
            print("Integrity check: Failed")

# Handler to send messages in mode c
def handle_send_data_c(conn,server_private_key,client_public_key):
    while True:
        # Reads the message from the terminal
        message = input("Enter data: ").encode("utf-8")
        # Signs the message using the function sign_message
        signature = sign_message(message, server_private_key)
        # Encrypts the message using the function encrypt_message
        encrypted_message = encrypt_message(message,client_public_key)
        # Combines the signature with the encrypted message
        combined_data= signature + b'split' + encrypted_message
        # Sends the combination to the other side
        conn.send(combined_data)

# Handler to receives messages in mode c
def handle_receive_data_c(conn,server_private_key,client_public_key):           
    while True:
        # Receives the combined data
        combined_data = conn.recv(4096)
        # Splits the message
        signature, encrypted_message = combined_data.rsplit(b'split', 1)
        # Decrypt the message
        decrypted_message = decrypt_message(encrypted_message,server_private_key)
       
         # Verifies the signature and returns the result of verification and the decrypted message
        if (verify_signature(decrypted_message, signature, client_public_key)):
            print("Signature verified. Message:", decrypted_message.decode())
        else:
            print("Signature verification failed.")

def start_server():
    # Ip from local host
    host = '127.0.0.1'
    port = 5555
    # Socket creation and connection with the server and waits from a connection from a client
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    # Success in the connection
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")
    # Sends the security modes to the client
    conn.send("Choose an option: A(Integrity), B(Integrity and confidentiality), or C(Integrity,confidentiality and authenticity): ".encode("utf_8"))
    # Receives the answer from the client
    choice = conn.recv(1).decode("utf-8")
    print("The client chose option "+ choice)
    # Enters the option chose by the client
    if choice == 'A' or choice == 'B' or choice == 'C' or choice == 'a' or choice == 'b' or choice == 'c':
        if choice == 'A' or choice == 'a':
            while True:
                # Start another thread for receiving data
                receive_thread = threading.Thread(target=handle_receive_data_a, args=(conn,))
                receive_thread.start()
                 # Start a thread for sending data
                send_thread = threading.Thread(target=handle_send_data_a, args=(conn,))
                send_thread.start()
                
                send_thread.join()
                receive_thread.join()

        elif choice == 'B'or choice == 'b':
            # Receives the public key from the client
            client_public_key_bytes = conn.recv(1024)
            client_public_key = load_pem_public_key(client_public_key_bytes, backend=default_backend())
            # Sends to the client the public key from the server
            conn.send(public)
            # Derives the shared key that is going to be used to calculate the final key
            shared_key = private_key.exchange(client_public_key)
            # Derives the final key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data'
            )
            # Defines key as the final key and the one that will be used in the symmetric encryption
            key = derived_key.derive(shared_key)
            # Receives the iv with the hash
            combined_iv = conn.recv(1024).decode("utf-8")
            # Devides the iv from the hash
            iv = combined_iv[:-64]
            iv_b = iv.encode("utf-8")
            # Calculates the hash of the received iv
            iv_hash = hash_data(iv)
            received_iv_hash = combined_iv[-64:]
            # Verifies the integrity of the iv
            if iv_hash == received_iv_hash:
                print("IV integrity check")
            else:
                print("IV integrity compromised")
            while True:
                # Start a thread for receiving data
                receive_thread = threading.Thread(target=handle_receive_data_b, args=(conn,key,iv_b))
                receive_thread.start()
                 # Start a thread for sending data
                send_thread = threading.Thread(target=handle_send_data_b, args=(conn,key,iv_b))
                send_thread.start()
                
                send_thread.join()
                receive_thread.join()

        elif choice == 'C' or choice == 'c':
            # Generate key pair for the server
            server_private_key, server_public_key = generate_key_pair()

            # Send the server's public key to the client
            conn.sendall(serialize_key(server_public_key))

            # Receive the client's public key
            client_public_key_data = conn.recv(2048)
            client_public_key = serialization.load_pem_public_key(client_public_key_data, backend=default_backend())
            while True:
                # Start a thread for receiving data
                receive_thread = threading.Thread(target=handle_receive_data_c, args=(conn,server_private_key,client_public_key))
                receive_thread.start()
                # Start a thread for sending data
                send_thread = threading.Thread(target=handle_send_data_c, args=(conn,server_private_key,client_public_key))
                send_thread.start()
                
                send_thread.join()
                receive_thread.join()
         
    else:
        # Sends in case the client chose a invalid option 
        conn.send("Chose an invalid option!".encode("utf_8"))

    conn.close()

if __name__ == '__main__':
    start_server()