import os
import sys

# Try different import methods for get_random_bytes
try:
    # First try: pycryptodome (Crypto)
    from Crypto.Random import get_random_bytes
    print("Using Crypto.Random from pycryptodome")
except ImportError:
    try:
        # Second try: old pycrypto
        from Crypto.Random import get_random_bytes
        print(" Using Crypto.Random from pycrypto")
    except ImportError:
        try:
            # Third try: cryptography library
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            print(" Using cryptography fallback for random bytes")
            
            # Fallback function using cryptography
            def get_random_bytes(length):
                return os.urandom(length)
        except ImportError:
            # Final fallback: use os.urandom directly
            print(" Using os.urandom fallback")
            def get_random_bytes(length):
                return os.urandom(length)

def generate_key(algorithm: str, key_size: int = None) -> bytes:
    """Generate appropriate key for algorithm"""
    if algorithm.upper() == 'AES':
        if key_size == 128:
            return get_random_bytes(16)
        elif key_size == 192:
            return get_random_bytes(24)
        elif key_size == 256:
            return get_random_bytes(32)
        else:
            raise ValueError(f"Unsupported AES key size: {key_size}")
    
    elif algorithm.upper() == 'CHACHA20':
        return get_random_bytes(32)  # 256-bit key
    
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def save_key(key: bytes, file_path: str):
    """Save key to file"""
    with open(file_path, 'wb') as f:
        f.write(key)

def load_key(file_path: str) -> bytes:
    """Load key from file"""
    with open(file_path, 'rb') as f:
        return f.read()