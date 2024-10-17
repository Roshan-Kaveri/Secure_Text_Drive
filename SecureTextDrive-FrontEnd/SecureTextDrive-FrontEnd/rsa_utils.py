from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


# Function to generate RSA key pair
def generate_rsa_key_pair(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Function to encrypt data using RSA
def rsa_encrypt(public_key, data):
    # Ensure the data is in bytes
    byte_data = data.encode('utf-8')

    # Calculate the maximum length of data that can be encrypted
    max_length = public_key.key_size // 8 - 2 * hashes.SHA256().digest_size - 2

    if len(byte_data) > max_length:
        raise ValueError("Data is too large to encrypt with RSA")

    encrypted_data = public_key.encrypt(
        byte_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data  # Return the encrypted data in bytes


# Function to decrypt data using RSA
def rsa_decrypt(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')  # Return the decrypted data as a string


# Serialize the private key to store it if needed
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for storage
    )


# Serialize the public key to store it if needed
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
