import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from algorithms.aes_cipher import AESCipher
from utils.file_utils import create_sample_file, ensure_data_directory
from utils.key_generator import generate_key

def test_aes_encryption():
    """Test AES encryption/decryption"""
    print("Testing AES Encryption...")
    
    # Ensure data directory exists
    ensure_data_directory()
    
    # Create sample file
    sample_file = create_sample_file(10)  # 10KB file
    print(f"Created sample file: {sample_file}")
    
    # Initialize AES cipher
    aes = AESCipher()
    print("AES cipher initialized")
    
    # Generate key
    key = generate_key('AES', 256)
    print(f"Generated key: {len(key)} bytes ({len(key)*8} bits)")
    
    # Test CBC mode
    print("\nTesting CBC Mode...")
    encrypt_result = aes.encrypt_file(sample_file, key, mode='CBC')
    print(f"Encryption completed: {encrypt_result['processing_time']:.4f}s")
    
    decrypt_result = aes.decrypt_file(
        encrypt_result['output_file'], 
        key, 
        mode='CBC'
    )
    print(f"Decryption completed: {decrypt_result['processing_time']:.4f}s")
    print(f"CBC - Total time: {encrypt_result['processing_time'] + decrypt_result['processing_time']:.4f}s")
    
    # Test GCM mode
    print("\nTesting GCM Mode...")
    encrypt_result_gcm = aes.encrypt_file(sample_file, key, mode='GCM')
    print(f"Encryption completed: {encrypt_result_gcm['processing_time']:.4f}s")
    
    decrypt_result_gcm = aes.decrypt_file(
        encrypt_result_gcm['output_file'], 
        key, 
        mode='GCM'
    )
    print(f"Decryption completed: {decrypt_result_gcm['processing_time']:.4f}s")
    print(f"GCM - Total time: {encrypt_result_gcm['processing_time'] + decrypt_result_gcm['processing_time']:.4f}s")
    
    # Performance comparison
    print("\nPerformance Comparison:")
    print(f"   CBC Mode: {encrypt_result['processing_time'] + decrypt_result['processing_time']:.4f}s total")
    print(f"   GCM Mode: {encrypt_result_gcm['processing_time'] + decrypt_result_gcm['processing_time']:.4f}s total")
    
    print("\n All tests completed successfully!")

if __name__ == "__main__":
    test_aes_encryption()