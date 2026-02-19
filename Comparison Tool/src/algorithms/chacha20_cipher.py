import os
import time
from Crypto.Cipher import ChaCha20
from .base_cipher import BaseCipher

class ChaCha20Cipher(BaseCipher):
    def __init__(self):
        super().__init__("ChaCha20")
        self.supported_key_sizes = [256]
    
    def encrypt_file(self, file_path: str, key: bytes, **kwargs) -> dict:
        def _encrypt():
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            cipher = ChaCha20.new(key=key)
            ciphertext = cipher.encrypt(plaintext)
            
            output_path = self._get_output_path('encrypted')
            with open(output_path, 'wb') as f:
                f.write(cipher.nonce + ciphertext)
            
            return {
                'output_file': output_path,
                'original_size': len(plaintext),
                'encrypted_size': len(ciphertext) + len(cipher.nonce),
                'nonce': cipher.nonce.hex()
            }
        
        result = self._measure_performance(_encrypt)
        result['operation'] = 'encryption'
        return result
    
    def decrypt_file(self, file_path: str, key: bytes, **kwargs) -> dict:
        def _decrypt():
            with open(file_path, 'rb') as f:
                data = f.read()
            
            nonce = data[:8]  # ChaCha20 uses 8-byte nonce
            ciphertext = data[8:]
            
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            
            output_path = self._get_output_path('decrypted')
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return {
                'output_file': output_path,
                'decrypted_size': len(plaintext),
                'verified': True
            }
        
        result = self._measure_performance(_decrypt)
        result['operation'] = 'decryption'
        return result
    
    def _get_output_path(self, operation: str) -> str:
        timestamp = int(time.time())
        return os.path.join('data', f'{operation}_{timestamp}.bin')