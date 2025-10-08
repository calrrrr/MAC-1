# COSC2536 - Security in Computing and Information Technology
# Assignment 2 (Semester 2, 2025)
# Task 1: AES CBC Mode Decryption

# This script decrypts a ciphertext that was encrypted using AES in CBC mode with PKCS7 padding.
# The AES key and ciphertext are provided in the input file "task1.txt".

# The program:
#   1. Reads the AES key and ciphertext from the input file
#   2. Extracts the IV (initialization vector) from the first
#      16 bytes of the ciphertext
#   3. Decrypts the ciphertext using AES-CBC
#   4. Removes the PKCS7 padding to get the original plaintext
#   5. Saves the plaintext in the output file
#   6. Displays the plaintext on the screen

# Import necessary cryptographic and file-handling libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

# File path setup
# BASE: absolute path of the folder where this Python file is located, to ensure the code works on any OS.
# IN: path to the input file containing the AES key and ciphertext.
# OUT: path to the output file where the decrypted plaintext will be saved.
BASE = os.path.dirname(os.path.abspath(__file__))
IN   = os.path.join(BASE, "input",  "task1.txt")
OUT  = os.path.join(BASE, "output", "task1_decrypted.txt")

# Function Description: Reads AES key and ciphertext (in hex), extracts the IV, decrypts using AES-CBC,
# removes PKCS7 padding, write plaintext to output file, and prints it.
def decrypt_task1(in_path, out_path):
    
    # Read all non-empty lines from the input file
    with open(in_path, "r") as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    # Extract the AES key (hex string) from the line starting with "CBC Key:"
    key_hex = next(ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("cbc key:"))
    
    # Locate the line where ciphertext begins (after the header "CBC Ciphertext:")
    ci = next(i for i, ln in enumerate(lines) if ln.lower().startswith("cbc ciphertext"))
    
    # The ciphertext is expected to be on the line right after that header
    ct_hex = next(ln for ln in lines[ci+1:] if ln) 

    # Convert the key and ciphertext from hex strings to bytes
    key = bytes.fromhex(key_hex)
    blob = bytes.fromhex(ct_hex)
    
    # The first 16 bytes of the ciphertext blob is the IV, the rest form the actual ciphertext
    iv, ct = blob[:16], blob[16:]           

    # Create a decryptor object to perform the decryption ooperationi in CBC mode using the extracted key and IV
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    
    # Perform the decryption, but this still includes PKCS7 padding at the end
    padded = decryptor.update(ct) + decryptor.finalize()

    # Create an unpadder for PKSC7 padding 
    unpad = PKCS7(algorithms.AES.block_size).unpadder()
    
    # Remove the padding to retrieve the original plaintext
    plain = unpad.update(padded) + unpad.finalize()

    # Create the output directory if it doesn't exist
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    # Write the decrypted plaintext to the output file
    with open(out_path, "wb") as f:
        f.write(plain)

    # Print the decrypted plaintext to the screen, ignoring any decoding errors
    print("Decrypted message:\n", plain.decode(errors="ignore"))

decrypt_task1(IN, OUT)

# Reference:
# - Lecture materials provided by COSC2536 course - L4-Code
# - Split file into lists - https://www.geeksforgeeks.org/python/how-to-split-a-file-into-a-list-in-python/
# - Python File Open - https://www.w3schools.com/python/python_file_open.asp
