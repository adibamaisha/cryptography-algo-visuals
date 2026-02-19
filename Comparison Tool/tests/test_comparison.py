import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from algorithms.aes_cipher import AESCipher
from algorithms.chacha20_cipher import ChaCha20Cipher
from analysis.performance_analyzer import PerformanceAnalyzer
from utils.file_utils import create_sample_file, ensure_data_directory

def test_algorithm_comparison():
    """Compare multiple algorithms"""
    print(" Algorithm Comparison Test")
    print("=" * 50)
    
    # Ensure data directory exists
    ensure_data_directory()
    
    # Create sample file
    sample_file = create_sample_file(100)  # 100KB file for better measurement
    file_size_kb = os.path.getsize(sample_file) / 1024
    print(f" Test file: {sample_file} ({file_size_kb:.1f} KB)")
    
    # Initialize algorithms
    algorithms = {
        'AES-CBC': AESCipher(),
        'AES-GCM': AESCipher(),
        'ChaCha20': ChaCha20Cipher()
    }
    
    # Initialize analyzer
    analyzer = PerformanceAnalyzer()
    
    print("\n Running performance benchmarks...")
    
    # Test each algorithm
    for name, algo in algorithms.items():
        print(f"\n Testing {name}...")
        
        if 'AES' in name:
            key_size = 256
            mode = 'GCM' if 'GCM' in name else 'CBC'
        else:
            key_size = 256
            mode = None
        
        from utils.key_generator import generate_key
        key = generate_key('AES' if 'AES' in name else 'CHACHA20', key_size)
        
        # Single run for quick feedback
        if mode:
            encrypt_result = algo.encrypt_file(sample_file, key, mode=mode)
        else:
            encrypt_result = algo.encrypt_file(sample_file, key)
        
        if mode:
            decrypt_result = algo.decrypt_file(encrypt_result['output_file'], key, mode=mode)
        else:
            decrypt_result = algo.decrypt_file(encrypt_result['output_file'], key)
        
        total_time = encrypt_result['processing_time'] + decrypt_result['processing_time']
        throughput = (file_size_kb / 1024) / total_time  # MB/s
        
        print(f"     Time: {total_time:.4f}s")
        print(f"    Throughput: {throughput:.2f} MB/s")
        print(f"    Memory: {encrypt_result['memory_used_mb']:.2f} MB")
    
    print("\nComparison test completed!")

if __name__ == "__main__":
    test_algorithm_comparison()