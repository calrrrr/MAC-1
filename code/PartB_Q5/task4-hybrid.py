import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

BASE = os.path.dirname(os.path.abspath(__file__))

# generate rsa keys
def gen_keys():

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# hybrid encryption
def hybrid_enc(input_file_path, public_key, enc_file_path, enc_key_path):

    # read task2.txt file
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # generate aes key and iv
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # aes encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # encrypt aes key using rsa
    enc_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # transfer aes key and rsa encyrpted data info files to display
    with open(enc_key_path, "wb") as f:
        f.write(enc_aes_key)
    with open(enc_file_path, "wb") as f:
        f.write(iv + ciphertext)

    print("AES Key:", aes_key.hex())
    print("")
    print("Encrypted AES Key:", enc_aes_key.hex())
    print("")
    print("Ciphertext Location : output")

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

    # aes decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(dec_file_path, "wb") as f:
        f.write(plaintext)

    print("Decrypted text written to:", dec_file_path)

def main():
    private_key, public_key = gen_keys()

    input_file_path = os.path.join(BASE, "input", "task2.txt")
    enc_file_path = os.path.join(BASE, "output", "task2_enc")
    dec_file_path = os.path.join(BASE, "output", "task2_dec")
    enc_key_path = os.path.join(BASE, "output", "enc_aes_key.bin")

    hybrid_enc(input_file_path, public_key, enc_file_path, enc_key_path)
    hybrid_dec(enc_file_path, enc_key_path, private_key, dec_file_path)

    print("All operations completed.")

if __name__ == "__main__":
    main()
