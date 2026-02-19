#!/usr/bin/env python3
"""
Cryptography Algorithm Comparison Tool
"""

import os
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Dict, List

from algorithms.aes_cipher import AESCipher
from algorithms.chacha20_cipher import ChaCha20Cipher
from analysis.performance_analyzer import PerformanceAnalyzer
from analysis.advanced_analyzer import AdvancedAnalyzer
from utils.file_utils import ensure_data_directory, create_sample_file
from utils.key_generator import generate_key

console = Console()

class CryptoComparisonTool:
    def __init__(self):
        self.algorithms = {
            'AES-CBC': AESCipher(),
            'AES-GCM': AESCipher(),
            'ChaCha20': ChaCha20Cipher()
        }
        self.performance_analyzer = PerformanceAnalyzer()
        self.advanced_analyzer = AdvancedAnalyzer()
        ensure_data_directory()
    
    def compare_algorithms(self, file_path: str, detailed: bool = False):
        """Compare all algorithms with optional detailed analysis"""
        console.print(Panel("🔬 Algorithm Comparison", style="blue"))
        
        if not os.path.exists(file_path):
            console.print(f"[red]Error: File '{file_path}' not found[/red]")
            return
        
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        console.print(f" File: {file_path} ({file_size_mb:.2f} MB)")
        
        # Get performance comparison using PerformanceAnalyzer
        try:
            # Use the performance analyzer to get basic metrics
            comparison_results = {}
            for algo_name, algorithm in self.algorithms.items():
                # Generate appropriate key
                if 'AES' in algo_name:
                    key = generate_key('AES', 256)
                    mode = 'GCM' if 'GCM' in algo_name else 'CBC'
                else:
                    key = generate_key('CHACHA20', 256)
                    mode = None
                
                # Run encryption and decryption
                if mode:
                    encrypt_result = algorithm.encrypt_file(file_path, key, mode=mode)
                    decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key, mode=mode)
                else:
                    encrypt_result = algorithm.encrypt_file(file_path, key)
                    decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key)
                
                total_time = encrypt_result['processing_time'] + decrypt_result['processing_time']
                throughput = file_size_mb / total_time if total_time > 0 else 0
                
                comparison_results[algo_name] = {
                    'encryption_time': encrypt_result['processing_time'],
                    'decryption_time': decrypt_result['processing_time'],
                    'total_time': total_time,
                    'throughput_mbps': throughput,
                    'memory_used_mb': encrypt_result['memory_used_mb'],
                    'file_size': os.path.getsize(file_path)
                }
            
            if detailed and hasattr(self.advanced_analyzer, 'create_detailed_comparison_table'):
                # Detailed analysis with advanced analyzer
                console.print("\n")
                detailed_table = self.advanced_analyzer.create_detailed_comparison_table(comparison_results, file_path)
                console.print(detailed_table)
            else:
                # Basic performance table
                table = Table(title="Algorithm Performance Comparison")
                table.add_column("Algorithm", style="cyan")
                table.add_column("Encrypt Time", style="green")
                table.add_column("Decrypt Time", style="green")
                table.add_column("Total Time", style="green")
                table.add_column("Throughput", style="yellow")
                table.add_column("Memory", style="magenta")
                
                for algo_name, results in comparison_results.items():
                    table.add_row(
                        algo_name,
                        f"{results['encryption_time']:.4f}s",
                        f"{results['decryption_time']:.4f}s",
                        f"{results['total_time']:.4f}s",
                        f"{results['throughput_mbps']:.2f} MB/s",
                        f"{results['memory_used_mb']:.2f} MB"
                    )
                
                console.print(table)
            
            # Show recommendations
            self._print_recommendations(comparison_results)
            
        except Exception as e:
            console.print(f"[red]Error during comparison: {e}[/red]")
            # Fallback to simple manual comparison
            self._fallback_comparison(file_path)
    
    def _fallback_comparison(self, file_path: str):
        """Fallback comparison method if analyzers fail"""
        console.print("[yellow]Using fallback comparison method...[/yellow]")
        
        table = Table(title="Algorithm Performance Comparison (Fallback)")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Encrypt Time", style="green")
        table.add_column("Decrypt Time", style="green")
        table.add_column("Total Time", style="green")
        
        comparison_results = {}
        
        for algo_name, algorithm in self.algorithms.items():
            try:
                # Generate appropriate key
                if 'AES' in algo_name:
                    key = generate_key('AES', 256)
                    mode = 'GCM' if 'GCM' in algo_name else 'CBC'
                else:
                    key = generate_key('CHACHA20', 256)
                    mode = None
                
                # Run encryption and decryption
                if mode:
                    encrypt_result = algorithm.encrypt_file(file_path, key, mode=mode)
                    decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key, mode=mode)
                else:
                    encrypt_result = algorithm.encrypt_file(file_path, key)
                    decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key)
                
                total_time = encrypt_result['processing_time'] + decrypt_result['processing_time']
                
                table.add_row(
                    algo_name,
                    f"{encrypt_result['processing_time']:.4f}s",
                    f"{decrypt_result['processing_time']:.4f}s",
                    f"{total_time:.4f}s"
                )
                
                comparison_results[algo_name] = {
                    'encryption_time': encrypt_result['processing_time'],
                    'decryption_time': decrypt_result['processing_time'],
                    'total_time': total_time
                }
                
            except Exception as e:
                console.print(f"[red]Error testing {algo_name}: {e}[/red]")
                table.add_row(algo_name, "ERROR", "ERROR", "ERROR")
        
        console.print(table)
        if comparison_results:
            self._print_recommendations(comparison_results)
    
    def _print_recommendations(self, comparison_results: Dict):
        """Print algorithm recommendations based on results"""
        console.print("\n" + "="*60)
        console.print(" RECOMMENDATIONS")
        console.print("="*60)
        
        # Find best performers
        if comparison_results:
            fastest = min(comparison_results.items(), key=lambda x: x[1]['total_time'])
            
            console.print(f" [green]Fastest Overall: {fastest[0]} ({fastest[1]['total_time']:.4f}s)[/green]")
            
            # Calculate performance differences
            fastest_time = fastest[1]['total_time']
            for algo_name, results in comparison_results.items():
                if algo_name != fastest[0]:
                    slowdown = ((results['total_time'] - fastest_time) / fastest_time) * 100
                    console.print(f"   {algo_name} is {slowdown:.1f}% slower than {fastest[0]}")
        
        # Use case recommendations
        console.print("\n Use Case Recommendations:")
        console.print("  • Mobile/Performance: [bold]ChaCha20[/bold] - Fastest with good security")
        console.print("  • General Purpose: [bold]AES-GCM[/bold] - Authenticated encryption")
        console.print("  • Compatibility: [bold]AES-CBC[/bold] - Widely supported")
    
    def benchmark_algorithms(self, file_path: str, iterations: int = 3):
        """Run detailed benchmarks with multiple iterations"""
        console.print(Panel(" Advanced Benchmarking", style="blue"))
        
        if not os.path.exists(file_path):
            console.print(f"[red]Error: File '{file_path}' not found[/red]")
            return
        
        try:
            # Use performance analyzer for multi-iteration benchmarking
            benchmark_results = {}
            
            for algo_name, algorithm in self.algorithms.items():
                console.print(f"\n Benchmarking {algo_name}...")
                
                # Generate key
                if 'AES' in algo_name:
                    key = generate_key('AES', 256)
                else:
                    key = generate_key('CHACHA20', 256)
                
                # Run multiple iterations
                encryption_times = []
                decryption_times = []
                memory_usage = []
                
                for i in range(iterations):
                    mode = 'GCM' if 'GCM' in algo_name else 'CBC'
                    
                    if 'AES' in algo_name:
                        encrypt_result = algorithm.encrypt_file(file_path, key, mode=mode)
                        decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key, mode=mode)
                    else:
                        encrypt_result = algorithm.encrypt_file(file_path, key)
                        decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key)
                    
                    encryption_times.append(encrypt_result['processing_time'])
                    decryption_times.append(decrypt_result['processing_time'])
                    memory_usage.append(encrypt_result['memory_used_mb'])
                
                # Calculate statistics
                import statistics
                benchmark_results[algo_name] = {
                    'encryption_mean': statistics.mean(encryption_times),
                    'encryption_std': statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0,
                    'decryption_mean': statistics.mean(decryption_times),
                    'decryption_std': statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0,
                    'memory_mean': statistics.mean(memory_usage),
                    'iterations': iterations
                }
            
            # Display benchmark results
            table = Table(title=f"Advanced Benchmark Results ({iterations} iterations)")
            table.add_column("Algorithm", style="cyan")
            table.add_column("Encrypt Mean±Std", style="green")
            table.add_column("Decrypt Mean±Std", style="green")
            table.add_column("Memory Usage", style="magenta")
            
            for algo_name, results in benchmark_results.items():
                table.add_row(
                    algo_name,
                    f"{results['encryption_mean']:.4f}s ± {results['encryption_std']:.4f}s",
                    f"{results['decryption_mean']:.4f}s ± {results['decryption_std']:.4f}s",
                    f"{results['memory_mean']:.2f} MB"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error during benchmarking: {e}[/red]")

@click.group()
def cli():
    """Cryptography Algorithm Comparison Tool"""
    pass

@cli.command()
def list():
    """List available algorithms"""
    tool = CryptoComparisonTool()
    
    table = Table(title="Available Algorithms")
    table.add_column("Name", style="cyan")
    table.add_column("Key Sizes", style="green")
    table.add_column("Modes", style="yellow")
    table.add_column("Type", style="magenta")
    
    for name, algo in tool.algorithms.items():
        info = algo.get_algorithm_info()
        table.add_row(
            info['name'],
            ", ".join(map(str, info['supported_key_sizes'])),
            ", ".join(info['supported_modes']) if info['supported_modes'] else "N/A",
            info['type']
        )
    
    console.print(table)

@cli.command()
@click.argument('file_path')
@click.option('--algorithm', '-a', default='AES', help='Encryption algorithm')
@click.option('--key-size', '-k', default=256, help='Key size in bits')
@click.option('--mode', '-m', default='CBC', help='Encryption mode')
def encrypt(file_path, algorithm, key_size, mode):
    """Encrypt a file"""
    tool = CryptoComparisonTool()
    
    if algorithm.upper() not in ['AES', 'CHACHA20']:
        console.print(f"[red]Error: Algorithm '{algorithm}' not supported[/red]")
        return
    
    key = generate_key(algorithm, key_size)
    console.print(f"[blue]Encrypting {file_path} with {algorithm}-{key_size}-{mode}[/blue]")
    
    if algorithm.upper() == 'AES':
        algo_instance = AESCipher()
        result = algo_instance.encrypt_file(file_path, key, mode=mode)
    else:
        algo_instance = ChaCha20Cipher()
        result = algo_instance.encrypt_file(file_path, key)
    
    # Display results
    table = Table(title="Encryption Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Algorithm", f"{algorithm}-{key_size}-{mode}")
    table.add_row("Processing Time", f"{result['processing_time']:.4f} seconds")
    table.add_row("Memory Used", f"{result['memory_used_mb']:.2f} MB")
    table.add_row("Original Size", f"{result['original_size']} bytes")
    table.add_row("Encrypted Size", f"{result['encrypted_size']} bytes")
    table.add_row("Size Overhead", f"{((result['encrypted_size'] - result['original_size']) / result['original_size'] * 100):.2f}%")
    table.add_row("Output File", result['output_file'])
    
    console.print(table)

@cli.command()
@click.argument('file_path')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed analysis')
def compare(file_path, detailed):
    """Compare performance of all algorithms"""
    tool = CryptoComparisonTool()
    tool.compare_algorithms(file_path, detailed)

@cli.command()
@click.argument('file_path')
@click.option('--iterations', '-i', default=3, help='Number of benchmark iterations')
def benchmark(file_path, iterations):
    """Run advanced benchmarking with multiple iterations"""
    tool = CryptoComparisonTool()
    tool.benchmark_algorithms(file_path, iterations)

@cli.command()
@click.option('--size', '-s', default=10, help='File size in KB')
def sample(size):
    """Create a sample file for testing"""
    tool = CryptoComparisonTool()
    sample_file = create_sample_file(size)
    console.print(f"[green]Created sample file: {sample_file}[/green]")
    console.print(f"[green]File size: {size} KB[/green]")

if __name__ == "__main__":
    cli()