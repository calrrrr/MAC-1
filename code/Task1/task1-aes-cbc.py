# task1-aes-cbc.py (compact)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

# works on any OS; matches the assignment's input/ output/ structure
BASE = os.path.dirname(os.path.abspath(__file__))
IN   = os.path.join(BASE, "input",  "task1.txt")
OUT  = os.path.join(BASE, "output", "task1_decrypted.txt")

def decrypt_task1(in_path, out_path):
    # Read key & ciphertext (both hex strings)
    with open(in_path, "r") as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    key_hex = next(ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("cbc key:"))
    ci = next(i for i, ln in enumerate(lines) if ln.lower().startswith("cbc ciphertext"))
    ct_hex = next(ln for ln in lines[ci+1:] if ln)   # first non-empty line after header

    key = bytes.fromhex(key_hex)
    blob = bytes.fromhex(ct_hex)
    iv, ct = blob[:16], blob[16:]                   # IV = first 16 bytes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpad = PKCS7(algorithms.AES.block_size).unpadder()
    plain = unpad.update(padded) + unpad.finalize()

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(plain)

decrypt_task1(IN, OUT)


    
