import os
import hashlib
from typing import Dict, List
from rich.table import Table
from rich.console import Console

console = Console()

class AdvancedAnalyzer:
    def __init__(self):
        self.security_scores = {
            'AES-CBC': {'security_bits': 256, 'quantum_safe': False, 'authentication': False},
            'AES-GCM': {'security_bits': 256, 'quantum_safe': False, 'authentication': True},
            'ChaCha20': {'security_bits': 256, 'quantum_safe': False, 'authentication': False}
        }
    
    def calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return 0.0
            
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy += -p_x * (p_x.bit_length() - 1)
            
            return entropy
        except:
            return 0.0
    
    def analyze_encryption_quality(self, original_file: str, encrypted_file: str) -> Dict:
        """Analyze how well the encryption worked"""
        original_entropy = self.calculate_entropy(original_file)
        encrypted_entropy = self.calculate_entropy(encrypted_file)
        
        original_size = os.path.getsize(original_file)
        encrypted_size = os.path.getsize(encrypted_file)
        
        return {
            'original_entropy': original_entropy,
            'encrypted_entropy': encrypted_entropy,
            'entropy_increase': encrypted_entropy - original_entropy,
            'size_overhead_percent': ((encrypted_size - original_size) / original_size) * 100,
            'compression_ratio': encrypted_size / original_size if original_size > 0 else 0
        }
    
    def generate_security_report(self, algorithm_name: str) -> Dict:
        """Generate security analysis for an algorithm"""
        security_info = self.security_scores.get(algorithm_name, {})
        
        score = security_info.get('security_bits', 0)
        if security_info.get('authentication'):
            score *= 1.1  # Bonus for authenticated encryption
        
        return {
            'algorithm': algorithm_name,
            'security_bits': security_info.get('security_bits', 0),
            'quantum_safe': security_info.get('quantum_safe', False),
            'authenticated': security_info.get('authentication', False),
            'security_score': score,
            'recommendation': self._get_security_recommendation(algorithm_name)
        }
    
    def _get_security_recommendation(self, algorithm: str) -> str:
        """Get security recommendation for an algorithm"""
        recommendations = {
            'AES-CBC': 'Good for general use, but consider GCM for authentication',
            'AES-GCM': 'Excellent for most applications - provides authentication',
            'ChaCha20': 'Excellent performance, good for mobile and constrained devices'
        }
        return recommendations.get(algorithm, 'No specific recommendation')
    
    def create_detailed_comparison_table(self, performance_results: Dict, file_path: str) -> Table:
        """Create a detailed comparison table with security metrics"""
        table = Table(title=" Detailed Algorithm Comparison", show_header=True, header_style="bold magenta")
        
        table.add_column("Algorithm", style="cyan", width=12)
        table.add_column("Perf Score", style="yellow", width=10)
        table.add_column("Security", style="green", width=10)
        table.add_column("Auth", style="blue", width=6)
        table.add_column("Quantum Safe", style="red", width=10)
        table.add_column("Throughput", style="yellow", width=12)
        table.add_column("Memory", style="magenta", width=10)
        table.add_column("Recommendation", style="white", width=30)
        
        # Calculate performance scores (inverse of total time)
        max_perf = max(1/results['total_time'] for results in performance_results.values())
        
        for algo_name, results in performance_results.items():
            security_info = self.generate_security_report(algo_name)
            
            # Performance score (0-100)
            perf_score = (1 / results['total_time']) / max_perf * 100
            
            table.add_row(
                algo_name,
                f"{perf_score:.1f}%",
                f"{security_info['security_bits']}-bit",
                "✓" if security_info['authenticated'] else "X",
                "✓" if security_info['quantum_safe'] else "X",
                f"{results['throughput_mbps']:.2f} MB/s",
                f"{results['memory_used_mb']:.2f} MB",
                security_info['recommendation']
            )
        
        return table