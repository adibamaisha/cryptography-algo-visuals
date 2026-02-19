import os
import json
import csv
from datetime import datetime
from typing import Dict, List

class BatchTester:
    def __init__(self):
        self.results = []
    
    def test_multiple_files(self, file_paths: List[str], output_format: str = 'json'):
        """Test multiple files and generate comprehensive report"""
        from ..algorithms.aes_cipher import AESCipher
        from ..algorithms.chacha20_cipher import ChaCha20Cipher
        from ..analysis.advanced_analyzer import SimpleAnalyzer
        
        algorithms = {
            'AES-CBC': AESCipher(),
            'AES-GCM': AESCipher(),
            'ChaCha20': ChaCha20Cipher()
        }
        analyzer = SimpleAnalyzer()
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                print(f"Testing {file_path}...")
                file_size = os.path.getsize(file_path)
                
                results = analyzer.compare_algorithms_simple(algorithms, file_path)
                
                for algo_name, result in results.items():
                    self.results.append({
                        'timestamp': datetime.now().isoformat(),
                        'file_path': file_path,
                        'file_size': file_size,
                        'algorithm': algo_name,
                        'encryption_time': result['encryption_time'],
                        'decryption_time': result['decryption_time'],
                        'total_time': result['total_time'],
                        'throughput': result['throughput_mbps'],
                        'memory_used': result['memory_used_mb']
                    })
        
        self._export_results(output_format)
    
    def _export_results(self, format: str):
        """Export results in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == 'json':
            filename = f"batch_results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
        
        elif format.lower() == 'csv':
            filename = f"batch_results_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                if self.results:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    writer.writerows(self.results)
        
        print(f"Results exported to: {filename}")