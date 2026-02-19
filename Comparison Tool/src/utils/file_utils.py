import os
import hashlib

def ensure_data_directory():
    """Ensure data directory exists"""
    os.makedirs('data', exist_ok=True)

def get_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_size(file_path: str) -> int:
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def create_sample_file(size_kb: int = 10) -> str:
    """Create a sample file for testing"""
    ensure_data_directory()
    file_path = os.path.join('data', f'sample_{size_kb}kb.bin')
    
    # Generate random data
    random_data = os.urandom(size_kb * 1024)
    
    with open(file_path, 'wb') as f:
        f.write(random_data)
    
    return file_path