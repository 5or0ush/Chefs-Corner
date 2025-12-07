import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

encrypted_recipe = (
    "gAAAAABpNYw6TLulJ3-hyXklzXHB1hgTsoXapErbNfQeWjnbscRR8P2F_xQNhu62"
    "bgDc4N3d2Zj-UhrOoCSlRBnTRA_GnWDbP8XhpZr-rLZdTTjO_tH3Iq6mZihE5vyu"
    "tIXcI-xRPB-0Uqek-UYHnl8NPFeym1kiMW54YkLd3TQAYJ3xq5ewp3ls0T6FjZ06"
    "xZG3nznWSrJeVyV-G1NoEgem3e4ugHP7UAy3y0X6Fs6LEYXlrXpz6LA="
)

def decrypt_with_key(encrypted_data: str, key: str) -> str:
    key_bytes = key.encode()
    salt = b"chefs_corner_salt"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    fernet = Fernet(derived_key)
    return fernet.decrypt(encrypted_data.encode()).decode()

if __name__ == "__main__":
    key = "weak-encryption-key-789"
    plaintext = decrypt_with_key(encrypted_recipe, key)
    print(plaintext)