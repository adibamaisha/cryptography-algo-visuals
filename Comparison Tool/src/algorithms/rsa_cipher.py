import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from .base_cipher import BaseCipher

# Fix imports by handling them differently
try:
    # Try relative import first (when running as package)
    from ..utils.key_generator import generate_key
    from .aes_cipher import AESCipher
except ImportError:
    # Fallback to absolute imports (when running directly)
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from utils.key_generator import generate_key
    from algorithms.aes_cipher import AESCipher

class RSACipher(BaseCipher):
    def __init__(self):
        super().__init__("RSA")
        self.supported_key_sizes = [1024, 2048, 4096]
        self.supported_modes = []  # RSA doesn't use modes like AES
    
    def generate_keypair(self, key_size: int = 2048):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    def encrypt_file(self, file_path: str, public_key: bytes, **kwargs) -> dict:
        """Encrypt file using RSA (hybrid encryption)"""
        def _encrypt():
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # RSA can only encrypt small data, so we use hybrid encryption
            # Generate a random AES key for the actual data encryption
            aes_key = generate_key('AES', 256)
            
            # Encrypt the AES key with RSA
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # Encrypt the actual data with AES
            aes = AESCipher()
            aes_result = aes.encrypt_file(file_path, aes_key, mode='GCM')
            
            # Save the encrypted AES key alongside the encrypted data
            key_file_path = aes_result['output_file'] + '.key'
            with open(key_file_path, 'wb') as f:
                f.write(encrypted_aes_key)
            
            return {
                'output_file': aes_result['output_file'],
                'key_file': key_file_path,
                'original_size': len(plaintext),
                'encrypted_size': aes_result['encrypted_size'],
                'key_size': len(encrypted_aes_key),
                'encrypted_key': encrypted_aes_key.hex()  # For display purposes
            }
        
        result = self._measure_performance(_encrypt)
        result['operation'] = 'encryption'
        return result
    
    def decrypt_file(self, file_path: str, private_key: bytes, **kwargs) -> dict:
        """Decrypt file using RSA (hybrid decryption)"""
        def _decrypt():
            # Get the key file path
            key_file_path = kwargs.get('key_file')
            if not key_file_path or not os.path.exists(key_file_path):
                raise ValueError("RSA key file is required for decryption")
            
            # Read the encrypted AES key
            with open(key_file_path, 'rb') as f:
                encrypted_aes_key = f.read()
            
            # Decrypt the AES key with RSA
            rsa_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Decrypt the actual data with AES
            aes = AESCipher()
            aes_result = aes.decrypt_file(file_path, aes_key, mode='GCM')
            
            return {
                'output_file': aes_result['output_file'],
                'decrypted_size': aes_result['decrypted_size'],
                'verified': aes_result.get('verified', True)
            }
        
        result = self._measure_performance(_decrypt)
        result['operation'] = 'decryption'
        return result
    
    def _get_output_path(self, operation: str) -> str:
        """Generate output file path"""
        timestamp = int(time.time())
        return os.path.join('data', f'{operation}_{timestamp}.bin')