# Chef's Corner - Recipe Website

A modern recipe website built with Flask and deployed on Vercel. Features a beautiful UI and comprehensive recipe collection.

## Features

- 🍳 Beautiful, responsive design
- 📱 Mobile-friendly interface
- 🔐 Admin authentication system
- 🍝 Curated recipe collection
- 🔒 Secure API endpoints
- 📊 Server configuration management

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export SERVER_SEED="your-secret-server-seed"
export SECRET_RECIPE_CONTENT="Your super secret recipe content here"
export ENCRYPTION_KEY="your-encryption-key-here"
```

3. Run the application:
```bash
python app.py
```

## RSA Key Generation

Before deploying, you need to generate RSA keys for JWT authentication:

### Generate Private Key:
```bash
openssl genrsa -out private_key.pem 2048
```

### Generate Public Key:
```bash
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### Extract keys for app.py:
```bash
# Get private key content
cat private_key.pem

# Get public key content  
cat public_key.pem
```

Replace the placeholder keys in `app.py` with the generated keys.

## Vercel Deployment

1. Install Vercel CLI:
```bash
npm i -g vercel
```

2. Set environment variables in Vercel:
```bash
vercel env add SERVER_SEED
vercel env add SECRET_RECIPE_CONTENT  
vercel env add ENCRYPTION_KEY
```

3. Deploy:
```bash
vercel --prod
```

## Environment Variables

- `SERVER_SEED`: Secret seed used for recipe ID generation
- `SECRET_RECIPE_CONTENT`: Content of the protected secret recipe
- `ENCRYPTION_KEY`: Key used for encrypting sensitive data

## API Endpoints

- `GET /` - Home page
- `GET /recipes` - Recipe listing page
- `GET /login` - Admin login page
- `POST /login` - Admin authentication
- `GET /api/recipes/{id}` - Get recipe by ID
- `GET /api/config` - Get server configuration (requires admin auth)
- `POST /api/encrypt` - Encrypt text using custom algorithm

## Security Features

- JWT-based authentication
- RSA public/private key cryptography
- Custom encryption for sensitive data
- Admin role-based access control

## Development Notes

This application was built with security best practices in mind. All sensitive data is properly encrypted and access is controlled through secure authentication mechanisms.

---

*Built with ❤️ by the Chef's Corner development team*
