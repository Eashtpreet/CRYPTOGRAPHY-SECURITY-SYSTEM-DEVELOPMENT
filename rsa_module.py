from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time

class RSAModule:
    def __init__(self):
        start = time.time()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.keygen_time = time.time() - start

    def encrypt(self, plaintext):
        data = plaintext.encode()
        if len(data) > 190:
            raise ValueError("RSA supports only small data. Use AES for large inputs.")

        start = time.time()
        ciphertext = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext, time.time() - start

    def decrypt(self, ciphertext):
        start = time.time()
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode(), time.time() - start
