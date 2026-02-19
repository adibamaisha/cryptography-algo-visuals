import os
import time
import statistics
from typing import Dict, List

class PerformanceAnalyzer:
    def __init__(self):
        self.results = {}
    
    def benchmark_algorithm(self, algorithm, file_path: str, key: bytes, iterations: int = 5) -> Dict:
        """Benchmark an algorithm with multiple iterations"""
        encryption_times = []
        decryption_times = []
        memory_usage = []
        
        for i in range(iterations):
            # Encryption
            encrypt_result = algorithm.encrypt_file(file_path, key, mode='CBC')
            encryption_times.append(encrypt_result['processing_time'])
            memory_usage.append(encrypt_result['memory_used_mb'])
            
            # Decryption
            decrypt_result = algorithm.decrypt_file(
                encrypt_result['output_file'], key, mode='CBC'
            )
            decryption_times.append(decrypt_result['processing_time'])
        
        return {
            'algorithm': algorithm.name,
            'encryption_mean': statistics.mean(encryption_times),
            'encryption_std': statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0,
            'decryption_mean': statistics.mean(decryption_times),
            'decryption_std': statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0,
            'memory_usage_mean': statistics.mean(memory_usage),
            'throughput_mbps': self._calculate_throughput(encryption_times, file_path),
            'iterations': iterations
        }
    
    def _calculate_throughput(self, times: List[float], file_path: str) -> float:
        """Calculate throughput in MB/s"""
        file_size = os.path.getsize(file_path)
        avg_time = statistics.mean(times)
        return (file_size / avg_time) / (1024 * 1024)  # MB/s
    
    def compare_algorithms(self, algorithms: Dict, file_path: str) -> Dict:
        """Compare multiple algorithms"""
        comparison = {}
        
        for algo_name, algorithm in algorithms.items():
            # Generate appropriate key for each algorithm
            key = self._generate_key(algo_name)
            
            # Run benchmark
            results = self.benchmark_algorithm(algorithm, file_path, key)
            comparison[algo_name] = results
        
        return comparison
    
    def _generate_key(self, algorithm_name: str) -> bytes:
        """Generate key for algorithm based on its name"""
        # Import here to avoid circular imports
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
        
        from utils.key_generator import generate_key
        
        if 'AES' in algorithm_name.upper():
            return generate_key('AES', 256)
        elif 'CHACHA20' in algorithm_name.upper():
            return generate_key('CHACHA20', 256)
        else:
            # Default to AES
            return generate_key('AES', 256)
    
    def generate_comparison_report(self, comparison_results: Dict) -> str:
        """Generate a formatted comparison report"""
        report = []
        report.append(" CRYPTOGRAPHY ALGORITHM COMPARISON REPORT")
        report.append("=" * 50)
        
        for algo_name, results in comparison_results.items():
            report.append(f"\n {algo_name}:")
            report.append(f"   Encryption: {results['encryption_mean']:.4f}s (±{results['encryption_std']:.4f}s)")
            report.append(f"   Decryption: {results['decryption_mean']:.4f}s (±{results['decryption_std']:.4f}s)")
            report.append(f"   Throughput: {results['throughput_mbps']:.2f} MB/s")
            report.append(f"   Memory: {results['memory_usage_mean']:.2f} MB")
            report.append(f"   Iterations: {results['iterations']}")
        
        return "\n".join(report)