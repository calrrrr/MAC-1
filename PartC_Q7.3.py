# libraries
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# using BASE
BASE = os.path.dirname(os.path.abspath(__file__))  
OUT_DIR = BASE                                     
KEYS_DIR = os.path.join(BASE, "keys")  
# modern reccomended key length fopr security             
KEY_SIZE = 2048                                    

os.makedirs(KEYS_DIR, exist_ok=True)

# key generation
def gen_keys():
    priv_key = rsa.generate_private_key(
        # creat public key using exponent 65537 like the original code
        public_exponent=65537,
        key_size=KEY_SIZE,
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

# takes the exponent (e) and modulus (n) from the public key numbers during generation
def public_key_tuple(public_key):
    
    # returns it, will use for formatting later
    numbers = public_key.public_numbers()
    return (numbers.e, numbers.n)

# encrypting the message using RSA with OAEP padding  to fix the issue bc the initial cipher uses textbook rsa without padding
# uses OAEP with MGF1 and SHA256 - used now modernly and taken from previous labs
def encrypt_message_oaep(public_key, message_bytes):
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

##################################################################
def main():

    # asks user to enter plaintext to encrypt
    plaintext = input("Enter data (alphabets only): ").strip()
    plaintext_bytes = plaintext.encode("utf-8")

    # RSA keys geenration
    print("Generating RSA keys")
    priv_key, pub_key = gen_keys()

    # RSA encryption with padding
    ciphertext_bytes = encrypt_message_oaep(pub_key, plaintext_bytes)

    # formatting
    cipher_int = int.from_bytes(ciphertext_bytes, byteorder="big")

    # output files
    key_txt_path = os.path.join(OUT_DIR, "key.txt") 
    cipher_txt_path = os.path.join(OUT_DIR, "cipher.txt")

    e, n = public_key_tuple(pub_key)
    
    with open(key_txt_path, "w") as f:
        f.write(f"({e}, {n})\n")

    with open(cipher_txt_path, "w") as f:
        f.write(str(cipher_int) + "\n")

    print(f"Public key location: {key_txt_path}")
    print(f"Ciphertext location: {cipher_txt_path}")

    print("Doneee!")

if __name__ == "__main__":
    main()
