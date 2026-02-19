import os
import time
from typing import Dict, Any
from Crypto.Cipher import AES  # Changed from Cryptodome to Crypto
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .base_cipher import BaseCipher

class AESCipher(BaseCipher):
    def __init__(self):
        super().__init__("AES")
        self.supported_key_sizes = [128, 192, 256]
        self.supported_modes = ['CBC', 'GCM', 'ECB']
    
    def encrypt_file(self, file_path: str, key: bytes, mode: str = 'CBC') -> Dict[str, Any]:
        """Encrypt a file using AES"""
        
        def _encrypt():
            # Read the file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            original_size = len(plaintext)
            
            if mode == 'CBC':
                return self._encrypt_cbc(plaintext, key)
            elif mode == 'GCM':
                return self._encrypt_gcm(plaintext, key)
            elif mode == 'ECB':
                return self._encrypt_ecb(plaintext, key)
            else:
                raise ValueError(f"Unsupported mode: {mode}")
        
        result = self._measure_performance(_encrypt)
        result['operation'] = 'encryption'
        return result
    
    def _encrypt_cbc(self, plaintext: bytes, key: bytes) -> Dict[str, Any]:
        """AES CBC mode encryption"""
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the plaintext to be multiple of block size
        padded_text = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        
        # Create output file path
        output_path = self._get_output_path('encrypted')
        
        # Write IV + ciphertext
        with open(output_path, 'wb') as f:
            f.write(iv + ciphertext)
        
        return {
            'output_file': output_path,
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext) + len(iv),
            'iv': iv.hex(),
            'mode': 'CBC'
        }
    
    def _encrypt_gcm(self, plaintext: bytes, key: bytes) -> Dict[str, Any]:
        """AES GCM mode encryption"""
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        output_path = self._get_output_path('encrypted')
        
        with open(output_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)
        
        return {
            'output_file': output_path,
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext) + len(cipher.nonce) + len(tag),
            'nonce': cipher.nonce.hex(),
            'tag': tag.hex(),
            'mode': 'GCM'
        }
    
    def _encrypt_ecb(self, plaintext: bytes, key: bytes) -> Dict[str, Any]:
        """AES ECB mode encryption (for educational purposes only - not secure!)"""
        cipher = AES.new(key, AES.MODE_ECB)
        
        # Pad the plaintext
        padded_text = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        
        output_path = self._get_output_path('encrypted')
        
        with open(output_path, 'wb') as f:
            f.write(ciphertext)
        
        return {
            'output_file': output_path,
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext),
            'mode': 'ECB',
            'warning': 'ECB mode is not secure for most purposes!'
        }
    
    def decrypt_file(self, file_path: str, key: bytes, mode: str = 'CBC', **kwargs) -> Dict[str, Any]:
        """Decrypt a file using AES"""
        
        def _decrypt():
            if mode == 'CBC':
                return self._decrypt_cbc(file_path, key)
            elif mode == 'GCM':
                return self._decrypt_gcm(file_path, key)
            elif mode == 'ECB':
                return self._decrypt_ecb(file_path, key)
            else:
                raise ValueError(f"Unsupported mode: {mode}")
        
        result = self._measure_performance(_decrypt)
        result['operation'] = 'decryption'
        return result
    
    def _decrypt_cbc(self, file_path: str, key: bytes) -> Dict[str, Any]:
        """AES CBC mode decryption"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        output_path = self._get_output_path('decrypted')
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'output_file': output_path,
            'decrypted_size': len(plaintext),
            'verified': True,
            'mode': 'CBC'
        }
    
    def _decrypt_gcm(self, file_path: str, key: bytes) -> Dict[str, Any]:
        """AES GCM mode decryption"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        output_path = self._get_output_path('decrypted')
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'output_file': output_path,
            'decrypted_size': len(plaintext),
            'verified': True,
            'mode': 'GCM'
        }
    
    def _decrypt_ecb(self, file_path: str, key: bytes) -> Dict[str, Any]:
        """AES ECB mode decryption"""
        with open(file_path, 'rb') as f:
            ciphertext = f.read()
        
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        output_path = self._get_output_path('decrypted')
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'output_file': output_path,
            'decrypted_size': len(plaintext),
            'verified': True,
            'mode': 'ECB',
            'warning': 'ECB mode is not secure for most purposes!'
        }
    
    def _get_output_path(self, operation: str) -> str:
        """Generate output file path"""
        timestamp = int(time.time())
        return os.path.join('data', f'{operation}_{timestamp}.bin')