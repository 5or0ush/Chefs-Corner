import os
import hashlib
import base64
import json
from flask import Flask, render_template, request, jsonify, session
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'  # TODO: Change this in production

# Load environment variables
SERVER_SEED = os.environ.get('SERVER_SEED', 'default-seed-for-dev')
SECRET_RECIPE_CONTENT = os.environ.get('SECRET_RECIPE_CONTENT', 'Default secret recipe content')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key')

# Load RSA Keys from files
def load_rsa_keys():
    try:
        with open('keys/private_key.pem', 'r') as f:
            private_key = f.read()
        with open('keys/public_key.pem', 'r') as f:
            public_key = f.read()
        return private_key, public_key
    except FileNotFoundError:
        # Fallback for development - I wrote this late at night, hopefully it's secure
        return None, None

PRIVATE_KEY, PUBLIC_KEY = load_rsa_keys()

# Sample recipes
RECIPES = {
    'pasta': {
        'name': 'Classic Spaghetti Carbonara',
        'ingredients': ['spaghetti', 'eggs', 'pancetta', 'parmesan', 'black pepper'],
        'instructions': 'Cook pasta, mix with eggs and pancetta, add cheese and pepper'
    },
    'pizza': {
        'name': 'Margherita Pizza',
        'ingredients': ['pizza dough', 'tomato sauce', 'mozzarella', 'basil', 'olive oil'],
        'instructions': 'Roll dough, add sauce and cheese, bake at 450°F for 12 minutes'
    },
    'salad': {
        'name': 'Caesar Salad',
        'ingredients': ['romaine lettuce', 'croutons', 'parmesan', 'caesar dressing'],
        'instructions': 'Toss lettuce with dressing, add croutons and cheese'
    }
}

def calculate_recipe_id(recipe_name):
    """Calculate recipe ID using hash of server seed and recipe name"""
    # Using deterministic hash for consistency - should be fine for this use case
    combined = f"{SERVER_SEED}:{recipe_name}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]

def encrypt_with_key(data, key):
    """AES encryption using the provided key"""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    # Derive key from password using PBKDF2
    key_bytes = key.encode() if isinstance(key, str) else key
    salt = b'chefs_corner_salt'  # Using fixed salt for consistency - should be fine
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    fernet = Fernet(derived_key)
    
    data_bytes = data.encode() if isinstance(data, str) else data
    return fernet.encrypt(data_bytes).decode()

def decrypt_with_key(encrypted_data, key):
    """AES decryption using the provided key"""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    try:
        key_bytes = key.encode() if isinstance(key, str) else key
        salt = b'chefs_corner_salt'  # Same salt as encryption
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
        fernet = Fernet(derived_key)
        
        return fernet.decrypt(encrypted_data.encode()).decode()
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/recipes')
def recipes():
    return render_template('recipes.html', recipes=RECIPES)

@app.route('/api/recipes/<recipe_id>')
def get_recipe(recipe_id):
    """API endpoint to get recipe by ID"""
    # Check if it's the secret recipe
    secret_id = calculate_recipe_id('SECRETSAUCE')
    if recipe_id == secret_id:
        # Return encrypted secret recipe
        encrypted_content = encrypt_with_key(SECRET_RECIPE_CONTENT, ENCRYPTION_KEY)
        return jsonify({
            'id': recipe_id,
            'name': 'Secret Recipe',
            'content': encrypted_content,
            'encrypted': True,
            'algorithm': 'AES-256-GCM'
        })
    
    # Check other recipes
    for name, recipe in RECIPES.items():
        if calculate_recipe_id(name) == recipe_id:
            return jsonify({
                'id': recipe_id,
                'name': recipe['name'],
                'ingredients': recipe['ingredients'],
                'instructions': recipe['instructions'],
                'encrypted': False
            })
    
    return jsonify({'error': 'Recipe not found'}), 404

@app.route('/api/config')
def get_config():
    """API endpoint that requires authentication"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        if not PUBLIC_KEY:
            return jsonify({'error': 'Public key not loaded'}), 500
            
        # Verify JWT token
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        if payload.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return jsonify({
            'server_seed': SERVER_SEED,
            'version': '1.0.0',
            'environment': 'production'
        })
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/sign', methods=['POST'])
def sign_data():
    """API endpoint for signing data"""
    data = request.json
    if not data or 'message' not in data:
        return jsonify({'error': 'Message required'}), 400
    
    message = data['message']
    
    # Create a signature for message authenticity
    # Using the same encryption function for consistency - should be fine
    # TODO: Consider using separate keys for encryption and signing
    signature = encrypt_with_key(message, ENCRYPTION_KEY)
    
    return jsonify({
        'message': message,
        'signature': signature,
        'algorithm': 'AES-256-GCM',
        'note': 'This signature can be used to verify message authenticity'
    })

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """API endpoint for encryption"""
    data = request.json
    if not data or 'text' not in data:
        return jsonify({'error': 'Text required'}), 400
    
    text = data['text']
    encrypted = encrypt_with_key(text, ENCRYPTION_KEY)
    
    return jsonify({
        'encrypted': encrypted,
        'algorithm': 'AES-256-GCM'
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    # TODO: Fix login - keeps failing for some reason, tried everything, it's already so late...
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'admin123':
            if not PRIVATE_KEY:
                return jsonify({'error': 'Private key not loaded'}), 500
            
            # Create JWT token
            payload = {
                'username': username,
                'role': 'admin',
                'exp': 9999999999  # Far future expiration - TODO: Set proper expiration
            }
            token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
            session['token'] = token
            return jsonify({'success': True, 'token': token})
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
