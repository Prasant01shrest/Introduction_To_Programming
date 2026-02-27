from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate a new RSA key pair (private key + public key)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Extract the public key from the private key
def encrypt_message(public_key, message):
    # Encrypt the message using RSA + OAEP padding
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encrypted data is returned as bytes
    return encrypted

# Decrypt an encrypted message using your private key
def decrypt_message(private_key, encrypted_message):
    # Decrypt the ciphertext using the private key
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Save the private and public keys into PEM files
def save_keys(private_key, public_key):
    # Save private key to "private_key.pem"
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to "public_key.pem"
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load a private key from the file "private_key.pem"
def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# Load a public key from the file "public_key.pem"
def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

# Convert a public key object into a PEM string
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
