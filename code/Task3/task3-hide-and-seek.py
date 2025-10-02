from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from PIL import Image
import piexif, os

BASE = os.path.dirname(os.path.abspath(__file__))
IN_IMG  = os.path.join(BASE, "input",  "photo.jpg")      # ensure this exists
OUT_IMG = os.path.join(BASE, "output", "secret.jpg")

KEY = bytes.fromhex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")

def encrypt(key, msg: bytes) -> bytes:
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(msg) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()

def decrypt(key, blob: bytes) -> bytes:
    iv, ct = blob[:16], blob[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()

def steg_write_jpeg(msg_bytes: bytes):
    os.makedirs(os.path.dirname(OUT_IMG), exist_ok=True)
    hex_blob = encrypt(KEY, msg_bytes).hex()

    im = Image.open(IN_IMG)
    exif_bytes = im.info.get("exif")
    if exif_bytes:
        exif = piexif.load(exif_bytes)
    else:
        exif = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}

    exif["0th"][piexif.ImageIFD.ImageDescription] = hex_blob
    im.save(OUT_IMG, exif=piexif.dump(exif))
    print("Saved:", OUT_IMG)

def steg_read_jpeg() -> bytes:
    im = Image.open(OUT_IMG)
    exif = piexif.load(im.info.get("exif"))  # tiny header lets piexif parse
    hex_blob = exif["0th"][piexif.ImageIFD.ImageDescription]
    if isinstance(hex_blob, bytes):
        hex_blob = hex_blob.decode("utf-8", "ignore")
    return decrypt(KEY, bytes.fromhex(hex_blob))

if __name__ == "__main__":
    msg = input("Enter the message to hide: ").encode()
    steg_write_jpeg(msg)
    revealed = steg_read_jpeg()
    print("Revealed:", revealed.decode("utf-8", errors="replace"))
