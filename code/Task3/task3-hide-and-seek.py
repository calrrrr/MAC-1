# COSC2536 - Security in Computing and Information Technology
# Assignment 2 (Semester 2, 2025)
# Task 3: Hide and Seek with AES-CBC and Steganography

# This script hides a secret text message inside a JPEG image using EXIF metadata.
# The message if first encrypted using AES in CBC mode with PKCS7 padding, and then stored in the image metadata.
# Later, the program can read the image, extract hidden encrypted data, decrypt it, and display the original message.

# Import necessary cryptographic and file-handling libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from PIL import Image
import piexif, os

# File path setup
# BASE: the folder containing this Python file
# IN_IMG: the source JPEG image used for hiding the message
# OUT_IMG: the new JPEG file that will contain the hidden message
BASE = os.path.dirname(os.path.abspath(__file__))
IN_IMG  = os.path.join(BASE, "input",  "photo.jpg")      # ensure this exists
OUT_IMG = os.path.join(BASE, "output", "secret.jpg")

# Hex key is converted into bytes
KEY = bytes.fromhex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")

# Function Description: Encrypts a message using AES in CBC mode. A random IV is generated each time.
# The function returns the IV prepended to the ciphertext.
def encrypt(key, msg: bytes) -> bytes:
    # Random 16-byte IV for CBC mode
    iv = os.urandom(16) 
    # AES block size is 128 bits
    padder = PKCS7(128).padder()
    # Apply PKSC7 padding to make data a multiple of 16 bytes
    padded = padder.update(msg) + padder.finalize()
    # Encrypt using AES_CBC
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    # Return IV concatenated with ciphertext
    return iv + enc.update(padded) + enc.finalize()

# Function Description: The function decrypts a ciphertext that was produced by the encyrpt() function above.
# It seperates the IV and the ciphertetxt, decrypts the data, and removes the PKCS7 padding.
def decrypt(key, blob: bytes) -> bytes:
    # Extract the first 16 bytes as the IV, the rest is the ciphertext
    iv, ct = blob[:16], blob[16:]
    # Create a decryptor object to perform the decryption ooperationi in CBC mode using the extracted key and IV
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    # Perform the decryption, but this still includes PKCS7 padding at the end
    padded = dec.update(ct) + dec.finalize()
    # Create an unpadder for PKSC7 padding
    unpad = PKCS7(128).unpadder()
    # Remove the padding to retrieve the original plaintext
    return unpad.update(padded) + unpad.finalize()

# Function Description: Encrypts the user's secret message and hides it inside a JPEG file's EXIF metadata.
def steg_write_jpeg(msg_bytes: bytes):
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(OUT_IMG), exist_ok=True)
    
    # Encrypt the message and convert to hex string for storage
    hex_blob = encrypt(KEY, msg_bytes).hex()

    # Open source image
    im = Image.open(IN_IMG)
    
    # Step 4: Load EXIF metadata if it exists, otherwise create a new template
    exif_bytes = im.info.get("exif")
    if exif_bytes:
        exif = piexif.load(exif_bytes)
    else:
        exif = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}

    # Store the encrypted hex string in the ImageDescription tag
    exif["0th"][piexif.ImageIFD.ImageDescription] = hex_blob

    # Save the modified image with the new EXIF data
    im.save(OUT_IMG, exif=piexif.dump(exif))
    print("Saved:", OUT_IMG)

# Function Description: Reads tbhe hidden message from the modified JPEG file, decrypts it back to its original form.
def steg_read_jpeg() -> bytes:
    # Open the stego image
    im = Image.open(OUT_IMG)
    # Read the exif data
    exif = piexif.load(im.info.get("exif"))  # tiny header lets piexif parse
    # retrive the hex string from the ImageDescription tag
    hex_blob = exif["0th"][piexif.ImageIFD.ImageDescription]
    # Convert from bytes to string if necessary
    if isinstance(hex_blob, bytes):
        hex_blob = hex_blob.decode("utf-8", "ignore")
    # Decrypt and return the original message
    return decrypt(KEY, bytes.fromhex(hex_blob))

# Main program execution
if __name__ == "__main__":
    # Get the secret message from the user
    msg = input("Enter the message to hide: ").encode()
    # Hide the message in the JPEG file
    steg_write_jpeg(msg)
    # Read back and decrypt the hidden message
    revealed = steg_read_jpeg()
    # Display the revealed message
    print("Revealed:", revealed.decode("utf-8", errors="replace"))

# Reference:
# - Lecture materials provided by COSC2536 course - L4-Code
# - Image Steganography with Python - https://medium.com/@stephanie.werli/image-steganography-with-python-83381475da57
