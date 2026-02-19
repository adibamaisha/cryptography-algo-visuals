import matplotlib.pyplot as plt
import numpy as np
import os
from typing import Dict, List

class ChartGenerator:
    def __init__(self):
        plt.style.use('seaborn-v0_8')
    
    def create_performance_chart(self, comparison_results: Dict, save_path: str = None):
        """Create performance comparison bar chart"""
        algorithms = list(comparison_results.keys())
        encryption_times = [results['encryption_time'] for results in comparison_results.values()]
        decryption_times = [results['decryption_time'] for results in comparison_results.values()]
        
        x = np.arange(len(algorithms))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(12, 8))
        rects1 = ax.bar(x - width/2, encryption_times, width, label='Encryption', color='skyblue')
        rects2 = ax.bar(x + width/2, decryption_times, width, label='Decryption', color='lightcoral')
        
        ax.set_xlabel('Algorithms')
        ax.set_ylabel('Time (seconds)')
        ax.set_title('Encryption/Decryption Performance Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels(algorithms)
        ax.legend()
        
        # Add value labels on bars
        self._autolabel(rects1, ax)
        self._autolabel(rects2, ax)
        
        fig.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"📊 Chart saved to: {save_path}")
        
        plt.show()
    
    def create_throughput_chart(self, comparison_results: Dict, save_path: str = None):
        """Create throughput comparison chart"""
        algorithms = list(comparison_results.keys())
        throughputs = [results['throughput_mbps'] for results in comparison_results.values()]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(algorithms, throughputs, color=['#ff9999', '#66b3ff', '#99ff99'])
        
        ax.set_xlabel('Algorithms')
        ax.set_ylabel('Throughput (MB/s)')
        ax.set_title('Algorithm Throughput Comparison')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                   f'{height:.2f} MB/s', ha='center', va='bottom')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        
        plt.show()
    
    def _autolabel(self, rects, ax):
        """Attach a text label above each bar displaying its height"""
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width()/2., height + 0.001,
                   f'{height:.4f}s', ha='center', va='bottom', fontsize=8)