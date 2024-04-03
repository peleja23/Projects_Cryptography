import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

#Calculate hash for the password
def hash_data(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.digest()

def encrypt(key, plaintext, associate_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)   
    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    # Authenticate additional data
    encryptor.authenticate_additional_data(associate_data)
    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def decrypt(iv, tag, key, ciphertext, associate_data):
    try:
        # Construct an AES-GCM "Decipher" object with the given key, IV, and tag
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(bytes(iv), bytes(tag)),
        ).decryptor()
        # Authenticate additional data
        decryptor.authenticate_additional_data(associate_data)
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except:
        # Handle the exception, e.g., log the error, raise a custom exception, etc.
        print("Authentication tag verification failed. The data may be corrupted or the password is wrong.")
        return ('Error in decryption.')

def mainencrypt(key,input_file,output_file):
    aad= b"authenticated but not encrypted payload"
    original = open(input_file)
    # Reading from file
    text=original.read()
    # Cipher the text
    ciphertext = encrypt(key, text, aad)
    with open(output_file,"wb") as encrypted:
        encrypted.write(ciphertext[0]) # Write IV in the file
        encrypted.write(ciphertext[1]) # Write ciphertext in the file
        encrypted.write(ciphertext[2]) # Write Tag in the file

def maindecrypt(key,input_file,output_file):
    aad= b"authenticated but not encrypted payload"
    with open(input_file, 'rb') as original:
        iv = original.read(12) # Read IV from the file
        ciphertext = original.read()
        tag = ciphertext[-16:] # Read Tag from the file
        total = ciphertext[:-16] # Read ciphertext from the file
    # Check if the given key matches the key used for encryption
    plaintext = decrypt(iv, tag, key, total, aad)
    with open(output_file,"w") as decrypted:
        decrypted.write(plaintext) # Write in a new file the result from decryption 

def main():
    # The user needs to give 5 arguments
    if len(sys.argv) != 5:
        print("Please insert the arguments in this order: python script.py -operation key input_file output_file")
        return
    operation = sys.argv[1] # Type of operation
    password = sys.argv[2] # Given password
    key = hash_data(password) # Calculates the key to a given password
    input_file = sys.argv[3] # Input file 
    # Check if the input file exists
    try:
        with open(input_file, 'r'):
            pass
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' does not exist.")
        return
    output_file = sys.argv[4] # Output file
    # Check what operation is needed or if its valid at all
    if operation == "cifra":
        mainencrypt(key, input_file, output_file)
        print(f"Encryption complete. Output written to {output_file}")
    elif operation == "decifra":
        maindecrypt(key, input_file, output_file)
        print(f"Decryption complete. Output written to {output_file}")
    else:
        print("Invalid operation. Use cifra or decifra.")

if __name__ == '__main__':
    main()