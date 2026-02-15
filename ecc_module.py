from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

class ECCModule:
    def __init__(self):
        start = time.time()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.keygen_time = time.time() - start

    def encrypt(self, plaintext):
        start = time.time()

        # Generate shared secret using ECDH
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)

        # Derive symmetric AES key from shared secret
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_key)
        aes_key = digest.finalize()[:16]  # AES-128 key

        # AES encryption
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return (ciphertext, iv), time.time() - start

    def decrypt(self, data):
        start = time.time()
        ciphertext, iv = data

        # Re-generate shared secret
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)

        # Derive AES key again
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_key)
        aes_key = digest.finalize()[:16]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plain) + unpadder.finalize()

        return plaintext.decode(), time.time() - start
