# libraries
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# BASE requirement for directory
BASE = os.path.dirname(os.path.abspath(__file__))

# generate rsa keys
def gen_keys():

    # creats 2048 bit rsa key with the common public exponent for balance of computation and security
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()

    # format public keys to pem so its easy to share for the user
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # same thing here but for private keys
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # displaying the keys
    print("RSA Public Key:")
    print(pub_pem.decode())
    print("")
    print("RSA Private Key:")
    print(priv_pem.decode())
    print("")

    # saving the public and private keys as files
    output_dir = os.path.join(BASE, "output")
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "rsa_pub_key.pem"), "wb") as f:
        f.write(pub_pem)
    with open(os.path.join(output_dir, "rsa_priv_key.pem"), "wb") as f:
        f.write(priv_pem)
    
    return priv_key, pub_key

# hybrid encryption by generating an aes key and encrypting that key using rsa
def hybrid_enc(input_file_path, pub_key, enc_file_path, enc_key_path):

    # reads task2.txt file
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # generate aes key and iv
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # aes encryption with cbc
    # the plaintext will be padded to multiples of 16 bytes using PKCS7 and then encyrpts it
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # encrypt aes key using rsa and OAEP padding which is more secure than textbook rsa
    enc_aes_key = pub_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # saves aes keys to file
    with open(enc_key_path, "wb") as f:
        f.write(enc_aes_key)
    with open(enc_file_path, "wb") as f:
        f.write(iv + ciphertext)
     # saving aes key to file
    with open(os.path.join(BASE, "output", "aes_key.bin"), "wb") as f:
        f.write(aes_key)


    # displays keys to console and notifies where ciphertext is outputted
    print("AES Key (before encryption):", aes_key.hex())
    print("")
    print("AES Key (after encryption):", enc_aes_key.hex())
    print("")
    print("Ciphertext made in output folder")
    print("")

# hybrid decryption
def hybrid_dec(enc_file_path, enc_key_path, private_key, dec_file_path):

    # read encrypted aes key and ciphertext
    with open(enc_key_path, "rb") as f:
        enc_aes_key = f.read()
    with open(enc_file_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    # decrypt aes key with private rsa key
    aes_key = private_key.decrypt(
        enc_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt aes result to file
    with open(os.path.join(BASE, "output", "aes_key_dec.bin"), "wb") as f:
        f.write(aes_key)

    # aes decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # saves decrypted aes as a file 
    with open(dec_file_path, "wb") as f:
        f.write(plaintext)

    # display to console
    print("Decrypted AES key in output folder")
    print("")
    print("Decrypted text in output folder")
    print("")

def main():
    # generates keys
    priv_key, pub_key = gen_keys()
    
    # sets up iput and output path for the files to go to
    input_file_path = os.path.join(BASE, "input", "task2.txt")
    enc_file_path = os.path.join(BASE, "output", "task2_enc")
    dec_file_path = os.path.join(BASE, "output", "task2_dec")
    enc_key_path = os.path.join(BASE, "output", "enc_aes_key.bin")

    hybrid_enc(input_file_path, pub_key, enc_file_path, enc_key_path)
    hybrid_dec(enc_file_path, enc_key_path, priv_key, dec_file_path)

if __name__ == "__main__":
    main()
