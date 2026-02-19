import time
import psutil
import threading
from rich.live import Live
from rich.table import Table
from rich.console import Console

console = Console()

class RealTimeMonitor:
    def __init__(self):
        self.metrics = {
            'cpu_percent': [],
            'memory_used': [],
            'encryption_ops': 0,
            'decryption_ops': 0
        }
        self.running = False
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join()
    
    def _monitor_loop(self):
        """Monitoring loop"""
        with Live(self._create_table(), refresh_per_second=4) as live:
            while self.running:
                time.sleep(0.25)
                live.update(self._create_table())
    
    def _create_table(self):
        """Create real-time monitoring table"""
        # Get current metrics
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        # Update metrics history
        self.metrics['cpu_percent'].append(cpu)
        self.metrics['memory_used'].append(memory.used / (1024**3))  # GB
        
        # Keep only last 10 readings
        for key in ['cpu_percent', 'memory_used']:
            if len(self.metrics[key]) > 10:
                self.metrics[key].pop(0)
        
        table = Table(title="🔍 Real-time System Monitoring")
        table.add_column("Metric", style="cyan")
        table.add_column("Current", style="green")
        table.add_column("Average", style="yellow")
        table.add_column("Max", style="red")
        
        # CPU row
        cpu_avg = sum(self.metrics['cpu_percent']) / len(self.metrics['cpu_percent'])
        cpu_max = max(self.metrics['cpu_percent'])
        table.add_row("CPU Usage", f"{cpu:.1f}%", f"{cpu_avg:.1f}%", f"{cpu_max:.1f}%")
        
        # Memory row
        memory_current = memory.used / (1024**3)
        memory_avg = sum(self.metrics['memory_used']) / len(self.metrics['memory_used'])
        memory_max = max(self.metrics['memory_used'])
        table.add_row("Memory Used", f"{memory_current:.1f} GB", f"{memory_avg:.1f} GB", f"{memory_max:.1f} GB")
        
        # Operations row
        table.add_row("Encryption Ops", str(self.metrics['encryption_ops']), "-", "-")
        table.add_row("Decryption Ops", str(self.metrics['decryption_ops']), "-", "-")
        
        return table
    
    def record_operation(self, operation_type: str):
        """Record an encryption/decryption operation"""
        if operation_type.lower() == 'encryption':
            self.metrics['encryption_ops'] += 1
        elif operation_type.lower() == 'decryption':
            self.metrics['decryption_ops'] += 1