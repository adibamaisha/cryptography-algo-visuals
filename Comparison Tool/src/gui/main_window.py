import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import time
import threading

from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from algorithms.aes_cipher import AESCipher
from algorithms.chacha20_cipher import ChaCha20Cipher
from algorithms.rsa_cipher import RSACipher
from analysis.performance_analyzer import PerformanceAnalyzer
from analysis.vulnerability_scanner import VulnerabilityScanner
from visualization.chart_generator import ChartGenerator
from testing.batch_tester import BatchTester
from monitoring.real_time_monitor import RealTimeMonitor
from utils.file_utils import create_sample_file, ensure_data_directory
from utils.key_generator import generate_key

class CryptoToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Algorithm Comparison Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize components
        self.algorithms = {
            'AES-CBC': AESCipher(),
            'AES-GCM': AESCipher(), 
            'ChaCha20': ChaCha20Cipher(),
            'RSA': RSACipher()
        }
        self.performance_analyzer = PerformanceAnalyzer()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.chart_generator = ChartGenerator()
        self.batch_tester = BatchTester()
        self.real_time_monitor = RealTimeMonitor()
        
        self.current_file = None
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_quick_test_tab()
        self.setup_advanced_analysis_tab()
        self.setup_security_scan_tab()
        self.setup_batch_testing_tab()
        self.setup_visualization_tab()
        self.setup_real_time_tab()
        
    def setup_quick_test_tab(self):
        """Setup the quick test tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🚀 Quick Test")
        
        # File selection
        file_frame = ttk.LabelFrame(tab, text="File Selection", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(file_frame, text="Select File", 
                  command=self.select_file).pack(side='left', padx=5)
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.pack(side='left', padx=10)
        
        ttk.Button(file_frame, text="Create Sample File", 
                  command=self.create_sample).pack(side='right', padx=5)
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(tab, text="Algorithm Configuration", padding=10)
        algo_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(algo_frame, text="Algorithm:").grid(row=0, column=0, sticky='w', padx=5)
        self.algo_var = tk.StringVar(value="AES-CBC")
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, 
                                 values=list(self.algorithms.keys()), state='readonly')
        algo_combo.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(algo_frame, text="Key Size:").grid(row=1, column=0, sticky='w', padx=5)
        self.key_size_var = tk.StringVar(value="256")
        key_combo = ttk.Combobox(algo_frame, textvariable=self.key_size_var,
                                values=["128", "192", "256", "1024", "2048", "4096"], state='readonly')
        key_combo.grid(row=1, column=1, padx=5, pady=2)
        
        # Operation buttons
        op_frame = ttk.Frame(tab)
        op_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(op_frame, text="🔒 Encrypt", 
                  command=self.encrypt_file, style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(op_frame, text="🔓 Decrypt", 
                  command=self.decrypt_file).pack(side='left', padx=5)
        ttk.Button(op_frame, text="⚡ Quick Compare", 
                  command=self.quick_compare).pack(side='left', padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(tab, text="Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.pack(fill='both', expand=True)
        
    def setup_advanced_analysis_tab(self):
        """Setup advanced analysis tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Advanced Analysis")
        
        # Configuration
        config_frame = ttk.LabelFrame(tab, text="Test Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(config_frame, text="Iterations:").grid(row=0, column=0, sticky='w', padx=5)
        self.iterations_var = tk.StringVar(value="5")
        ttk.Spinbox(config_frame, from_=1, to=100, textvariable=self.iterations_var,
                width=10).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="File Size (KB):").grid(row=0, column=2, sticky='w', padx=5)
        self.test_size_var = tk.StringVar(value="100")
        ttk.Spinbox(config_frame, from_=1, to=10000, textvariable=self.test_size_var,
                width=10).grid(row=0, column=3, padx=5, pady=2)
        
        # Algorithm selection
        ttk.Label(config_frame, text="Algorithms to Test:").grid(row=1, column=0, sticky='w', padx=5)
        self.algorithm_vars = {}
        algo_frame = ttk.Frame(config_frame)
        algo_frame.grid(row=1, column=1, columnspan=3, sticky='w', padx=5, pady=2)
        
        for i, algo in enumerate(self.algorithms.keys()):
            var = tk.BooleanVar(value=True)
            self.algorithm_vars[algo] = var
            ttk.Checkbutton(algo_frame, text=algo, variable=var).pack(side='left', padx=10)
        
        # Buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(button_frame, text="Run Advanced Benchmark", 
                command=self.run_advanced_benchmark).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export Results", 
                command=self.export_results).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear Results", 
                command=self.clear_advanced_results).pack(side='left', padx=5)
        
        # Create a PanedWindow for resizable results areas
        results_paned = ttk.PanedWindow(tab, orient=tk.VERTICAL)
        results_paned.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Summary Results Frame (Top)
        summary_frame = ttk.LabelFrame(results_paned, text="📈 Summary Results", padding=10)
        results_paned.add(summary_frame, weight=1)
        
        # Summary results table
        self.summary_tree = ttk.Treeview(summary_frame, columns=('Algorithm', 'Encrypt Time', 'Decrypt Time', 'Total Time', 'Throughput', 'Memory'), show='headings', height=8)
        
        # Configure columns
        self.summary_tree.heading('Algorithm', text='Algorithm')
        self.summary_tree.heading('Encrypt Time', text='Encrypt (s)')
        self.summary_tree.heading('Decrypt Time', text='Decrypt (s)')
        self.summary_tree.heading('Total Time', text='Total (s)')
        self.summary_tree.heading('Throughput', text='Throughput (MB/s)')
        self.summary_tree.heading('Memory', text='Memory (MB)')
        
        # Set column widths
        self.summary_tree.column('Algorithm', width=120)
        self.summary_tree.column('Encrypt Time', width=100)
        self.summary_tree.column('Decrypt Time', width=100)
        self.summary_tree.column('Total Time', width=100)
        self.summary_tree.column('Throughput', width=120)
        self.summary_tree.column('Memory', width=100)
        
        # Add scrollbar to summary table
        summary_scrollbar = ttk.Scrollbar(summary_frame, orient=tk.VERTICAL, command=self.summary_tree.yview)
        self.summary_tree.configure(yscrollcommand=summary_scrollbar.set)
        
        self.summary_tree.pack(side='left', fill='both', expand=True)
        summary_scrollbar.pack(side='right', fill='y')
        
        # Detailed Results Frame (Bottom)
        detailed_frame = ttk.LabelFrame(results_paned, text="📋 Detailed Results", padding=10)
        results_paned.add(detailed_frame, weight=1)
        
        self.advanced_results = scrolledtext.ScrolledText(detailed_frame, height=15)
        self.advanced_results.pack(fill='both', expand=True)
        
    def setup_security_scan_tab(self):
        """Setup security scanning tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 Security Scan")
        
        # Scan configuration
        config_frame = ttk.LabelFrame(tab, text="Scan Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(config_frame, text="Algorithm:").grid(row=0, column=0, sticky='w', padx=5)
        self.scan_algo_var = tk.StringVar(value="AES-CBC")
        ttk.Combobox(config_frame, textvariable=self.scan_algo_var,
                    values=list(self.algorithms.keys()), state='readonly').grid(row=0, column=1, padx=5)
        
        ttk.Label(config_frame, text="Key Size:").grid(row=0, column=2, sticky='w', padx=5)
        self.scan_key_var = tk.StringVar(value="256")
        ttk.Combobox(config_frame, textvariable=self.scan_key_var,
                    values=["128", "192", "256", "1024", "2048", "4096"]).grid(row=0, column=3, padx=5)
        
        ttk.Label(config_frame, text="Mode:").grid(row=1, column=0, sticky='w', padx=5)
        self.scan_mode_var = tk.StringVar(value="CBC")
        ttk.Combobox(config_frame, textvariable=self.scan_mode_var,
                    values=["CBC", "GCM", "ECB", "None"]).grid(row=1, column=1, padx=5)
        
        # Scan button
        ttk.Button(config_frame, text="Run Security Scan", 
                  command=self.run_security_scan).grid(row=1, column=3, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(tab, text="Security Report", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.security_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.security_text.pack(fill='both', expand=True)
        
    def setup_batch_testing_tab(self):
        """Setup batch testing tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📁 Batch Testing")
        
        # File selection
        file_frame = ttk.LabelFrame(tab, text="Files to Test", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        self.file_listbox = tk.Listbox(file_frame, height=6)
        self.file_listbox.pack(fill='x', padx=5, pady=5)
        
        button_frame = ttk.Frame(file_frame)
        button_frame.pack(fill='x', pady=5)
        
        ttk.Button(button_frame, text="Add Files", 
                  command=self.add_batch_files).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear List", 
                  command=self.clear_batch_files).pack(side='left', padx=5)
        
        # Export options
        export_frame = ttk.LabelFrame(tab, text="Export Options", padding=10)
        export_frame.pack(fill='x', padx=10, pady=5)
        
        self.export_format = tk.StringVar(value="json")
        ttk.Radiobutton(export_frame, text="JSON", variable=self.export_format, 
                       value="json").pack(side='left', padx=10)
        ttk.Radiobutton(export_frame, text="CSV", variable=self.export_format, 
                       value="csv").pack(side='left', padx=10)
        
        # Run button
        ttk.Button(tab, text="Run Batch Tests", 
                  command=self.run_batch_tests).pack(pady=10)
        
    def setup_visualization_tab(self):
        """Setup visualization tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📈 Visualization")
        
        # Chart options
        chart_frame = ttk.LabelFrame(tab, text="Chart Options", padding=10)
        chart_frame.pack(fill='x', padx=10, pady=5)
        
        self.chart_type = tk.StringVar(value="performance")
        ttk.Radiobutton(chart_frame, text="Performance Comparison", 
                       variable=self.chart_type, value="performance").pack(anchor='w')
        ttk.Radiobutton(chart_frame, text="Throughput Comparison", 
                       variable=self.chart_type, value="throughput").pack(anchor='w')
        
        ttk.Button(chart_frame, text="Generate Chart", 
                  command=self.generate_chart).pack(pady=10)
        
        # Chart info
        self.chart_info = ttk.Label(tab, text="Chart will be displayed in a separate window")
        self.chart_info.pack(pady=10)
        
    def setup_real_time_tab(self):
        """Setup real-time monitoring tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Real-time Monitor")
        
        # Monitor controls
        control_frame = ttk.LabelFrame(tab, text="Monitoring Controls", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Start Monitoring", 
                  command=self.start_monitoring).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Stop Monitoring", 
                  command=self.stop_monitoring).pack(side='left', padx=5)
        
        # Monitor display
        monitor_frame = ttk.LabelFrame(tab, text="System Metrics", padding=10)
        monitor_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.monitor_text = scrolledtext.ScrolledText(monitor_frame, height=15)
        self.monitor_text.pack(fill='both', expand=True)
        
        # Update monitor periodically
        self.monitor_running = False
        self.update_monitor()
        
    # === Core Functionality Methods ===
    
    def select_file(self):
        """Select a file for operations"""
        filename = filedialog.askopenfilename(
            title="Select file to process",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("PDF files", "*.pdf")]
        )
        if filename:
            self.current_file = filename
            self.file_label.config(text=os.path.basename(filename))
            
    def create_sample(self):
        """Create a sample file"""
        try:
            size = int(self.test_size_var.get())
            sample_file = create_sample_file(size)
            self.current_file = sample_file
            self.file_label.config(text=f"Sample ({size}KB)")
            self.log_result(f"✅ Created sample file: {sample_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create sample: {e}")
            
    def encrypt_file(self):
        """Encrypt the current file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
            
        try:
            algorithm = self.algo_var.get()
            key_size = int(self.key_size_var.get())
            
            if 'AES' in algorithm:
                key = generate_key('AES', key_size)
                mode = 'GCM' if 'GCM' in algorithm else 'CBC'
                result = self.algorithms[algorithm].encrypt_file(self.current_file, key, mode=mode)
                self.log_result(f"✅ Encryption completed in {result['processing_time']:.4f}s")
                self.log_result(f"📁 Output: {result['output_file']}")
                
            elif 'ChaCha20' in algorithm:
                key = generate_key('CHACHA20', key_size)
                result = self.algorithms[algorithm].encrypt_file(self.current_file, key)
                self.log_result(f"✅ Encryption completed in {result['processing_time']:.4f}s")
                self.log_result(f"📁 Output: {result['output_file']}")
                
            else:  # RSA
                # For RSA, we need to generate a keypair first
                private_key, public_key = self.algorithms[algorithm].generate_keypair(key_size)
                result = self.algorithms[algorithm].encrypt_file(self.current_file, public_key)
                
                self.log_result(f"✅ RSA Encryption completed in {result['processing_time']:.4f}s")
                self.log_result(f"📁 Encrypted File: {result['output_file']}")
                self.log_result(f"🔑 Key File: {result['key_file']}")
                self.log_result("💡 Save the private key securely for decryption!")
                
                # Save the private key to a file
                key_filename = f"rsa_private_key_{int(time.time())}.pem"
                with open(key_filename, 'wb') as f:
                    f.write(private_key)
                self.log_result(f"🔐 Private key saved as: {key_filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            
    def decrypt_file(self):
        """Decrypt a file"""
        filename = filedialog.askopenfilename(title="Select file to decrypt")
        if not filename:
            return
            
        try:
            # For simplicity, we'd need to track keys - this is a basic implementation
            messagebox.showinfo("Info", "Decryption would require the appropriate key")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            

    def quick_compare(self):
        """Quick comparison of all algorithms including RSA"""
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return
            
        def run_comparison():
            try:
                self.log_result("🔄 Running quick comparison (including RSA)...")
                
                results = {}
                rsa_key_info = {}  # Store RSA key information
                
                for algo_name, algorithm in self.algorithms.items():
                    self.log_result(f"Testing {algo_name}...")
                    
                    try:
                        if 'RSA' in algo_name:
                            # Handle RSA separately - it's much slower and uses hybrid encryption
                            private_key, public_key = algorithm.generate_keypair(2048)
                            encrypt_result = algorithm.encrypt_file(self.current_file, public_key)
                            
                            # Store key info for potential decryption
                            rsa_key_info[algo_name] = {
                                'private_key': private_key,
                                'key_file': encrypt_result.get('key_file')
                            }
                            
                            # For RSA, we'll measure encryption time only (decryption is similar)
                            # and note that it's hybrid encryption
                            total_time = encrypt_result['processing_time']
                            results[algo_name] = {
                                'time': total_time,
                                'type': 'asymmetric',
                                'encrypt_time': encrypt_result['processing_time'],
                                'throughput': 'N/A (hybrid)',
                                'note': 'Uses AES-256-GCM for data encryption'
                            }
                            
                        else:
                            # Symmetric algorithms (AES, ChaCha20)
                            if 'AES' in algo_name:
                                key = generate_key('AES', 256)
                                mode = 'GCM' if 'GCM' in algo_name else 'CBC'
                                encrypt_result = algorithm.encrypt_file(self.current_file, key, mode=mode)
                                decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key, mode=mode)
                            elif 'ChaCha20' in algo_name:
                                key = generate_key('CHACHA20', 256)
                                encrypt_result = algorithm.encrypt_file(self.current_file, key)
                                decrypt_result = algorithm.decrypt_file(encrypt_result['output_file'], key)
                            
                            total_time = encrypt_result['processing_time'] + decrypt_result['processing_time']
                            file_size_mb = os.path.getsize(self.current_file) / (1024 * 1024)
                            throughput = file_size_mb / total_time if total_time > 0 else 0
                            
                            results[algo_name] = {
                                'time': total_time,
                                'type': 'symmetric',
                                'encrypt_time': encrypt_result['processing_time'],
                                'decrypt_time': decrypt_result['processing_time'],
                                'throughput': throughput,
                                'memory': encrypt_result['memory_used_mb']
                            }
                            
                        self.log_result(f"   ✅ {algo_name} completed")
                        
                    except Exception as e:
                        self.log_result(f"   ❌ {algo_name} failed: {str(e)}")
                        results[algo_name] = {'time': float('inf'), 'error': str(e)}
                    
                # Display results in a organized way
                self.display_quick_comparison_results(results)
                
            except Exception as e:
                self.log_result(f"❌ Comparison failed: {e}")
                
        threading.Thread(target=run_comparison).start()

    def display_quick_comparison_results(self, results):
        """Display quick comparison results in an organized format"""
        self.log_result("\n" + "="*60)
        self.log_result("📊 QUICK COMPARISON RESULTS")
        self.log_result("="*60)
        
        # Separate symmetric and asymmetric results
        symmetric_results = {k: v for k, v in results.items() if v.get('type') == 'symmetric'}
        asymmetric_results = {k: v for k, v in results.items() if v.get('type') == 'asymmetric'}
        
        # Display symmetric algorithms first
        if symmetric_results:
            self.log_result("\n🔐 SYMMETRIC ALGORITHMS (Encryption + Decryption):")
            self.log_result("-" * 50)
            
            for algo, data in sorted(symmetric_results.items(), key=lambda x: x[1]['time']):
                if data['time'] == float('inf'):
                    self.log_result(f"   {algo:12} ❌ FAILED")
                else:
                    self.log_result(
                        f"   {algo:12} ⏱️  {data['time']:.4f}s "
                        f"(Enc: {data['encrypt_time']:.4f}s, Dec: {data['decrypt_time']:.4f}s) "
                        f"🚀 {data['throughput']:.2f} MB/s "
                        f"💾 {data['memory']:.2f} MB"
                    )
        
        # Display asymmetric algorithms
        if asymmetric_results:
            self.log_result("\n🔑 ASYMMETRIC ALGORITHMS (Encryption Only - Hybrid):")
            self.log_result("-" * 50)
            
            for algo, data in asymmetric_results.items():
                if data.get('error'):
                    self.log_result(f"   {algo:12} ❌ {data['error']}")
                else:
                    self.log_result(
                        f"   {algo:12} ⏱️  {data['encrypt_time']:.4f}s (encryption only) "
                        f"📝 {data.get('note', '')}"
                    )
        
        # Performance rankings and recommendations
        self.log_result("\n🎯 PERFORMANCE ANALYSIS")
        self.log_result("-" * 50)
        
        # Fastest symmetric algorithm
        valid_symmetric = {k: v for k, v in symmetric_results.items() if v['time'] != float('inf')}
        if valid_symmetric:
            fastest_symmetric = min(valid_symmetric.items(), key=lambda x: x[1]['time'])
            self.log_result(f"🏆 Fastest Symmetric: {fastest_symmetric[0]} ({fastest_symmetric[1]['time']:.4f}s)")
            
            # Show performance differences
            for algo, data in valid_symmetric.items():
                if algo != fastest_symmetric[0]:
                    slowdown = ((data['time'] - fastest_symmetric[1]['time']) / fastest_symmetric[1]['time']) * 100
                    self.log_result(f"   {algo} is {slowdown:.1f}% slower")
        
        # RSA performance context
        if asymmetric_results:
            rsa_algo = list(asymmetric_results.keys())[0]
            rsa_time = asymmetric_results[rsa_algo].get('encrypt_time', 0)
            
            if valid_symmetric:
                avg_symmetric_time = sum(data['time'] for data in valid_symmetric.values()) / len(valid_symmetric)
                if rsa_time > 0:
                    slowdown_factor = rsa_time / avg_symmetric_time
                    self.log_result(f"   {rsa_algo} is ~{slowdown_factor:.1f}x slower than symmetric algorithms")
        
        # Recommendations
        self.log_result("\n💡 RECOMMENDATIONS:")
        self.log_result("  • For large files: Use symmetric algorithms (AES/ChaCha20)")
        self.log_result("  • For key exchange: Use RSA with hybrid encryption")
        self.log_result("  • For mobile devices: Consider ChaCha20")
        self.log_result("  • For modern web: Use AES-GCM")
        
        # Security notes
        self.log_result("\n🔒 SECURITY NOTES:")
        self.log_result("  • All algorithms provide strong encryption when properly configured")
        self.log_result("  • RSA enables secure key exchange but is slower for bulk data")
        self.log_result("  • Hybrid encryption (RSA + AES) combines the best of both")

    def run_advanced_benchmark(self):
        """Run advanced benchmarking with detailed results display"""
        def run_benchmark():
            try:
                # Clear previous results
                self.clear_advanced_results()
                
                self.advanced_results.insert(tk.END, " Running advanced benchmark...\n\n")
                self.root.update()
                
                iterations = int(self.iterations_var.get())
                selected_algos = [algo for algo, var in self.algorithm_vars.items() if var.get()]
                
                if not selected_algos:
                    self.advanced_results.insert(tk.END, " Please select at least one algorithm to test.\n")
                    return
                
                # Create sample file for testing
                file_size = int(self.test_size_var.get())
                sample_file = create_sample_file(file_size)
                
                benchmark_results = {}
                
                for algo_name in selected_algos:
                    self.advanced_results.insert(tk.END, f" Testing {algo_name} ({iterations} iterations)...\n")
                    self.root.update()
                    
                    # Run multiple iterations
                    encryption_times = []
                    decryption_times = []
                    memory_usage = []
                    
                    for i in range(iterations):
                        try:
                            if 'AES' in algo_name:
                                key = generate_key('AES', 256)
                                mode = 'GCM' if 'GCM' in algo_name else 'CBC'
                                encrypt_result = self.algorithms[algo_name].encrypt_file(sample_file, key, mode=mode)
                                decrypt_result = self.algorithms[algo_name].decrypt_file(encrypt_result['output_file'], key, mode=mode)
                            elif 'ChaCha20' in algo_name:
                                key = generate_key('CHACHA20', 256)
                                encrypt_result = self.algorithms[algo_name].encrypt_file(sample_file, key)
                                decrypt_result = self.algorithms[algo_name].decrypt_file(encrypt_result['output_file'], key)
                            else:  # RSA
                                private_key, public_key = self.algorithms[algo_name].generate_keypair(2048)
                                encrypt_result = self.algorithms[algo_name].encrypt_file(sample_file, public_key)
                                # Note: RSA decryption would require the key file
                                decrypt_result = {'processing_time': 0, 'decrypted_size': encrypt_result['original_size']}
                            
                            encryption_times.append(encrypt_result['processing_time'])
                            decryption_times.append(decrypt_result['processing_time'])
                            memory_usage.append(encrypt_result['memory_used_mb'])
                            
                        except Exception as e:
                            self.advanced_results.insert(tk.END, f"     Iteration {i+1} failed: {e}\n")
                    
                    # Calculate statistics
                    if encryption_times and decryption_times:
                        import statistics
                        encrypt_mean = statistics.mean(encryption_times)
                        encrypt_std = statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0
                        decrypt_mean = statistics.mean(decryption_times)
                        decrypt_std = statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0
                        memory_mean = statistics.mean(memory_usage) if memory_usage else 0
                        total_time = encrypt_mean + decrypt_mean
                        
                        # Calculate throughput (MB/s)
                        file_size_mb = file_size / 1024  # Convert KB to MB
                        throughput = file_size_mb / total_time if total_time > 0 else 0
                        
                        benchmark_results[algo_name] = {
                            'encrypt_mean': encrypt_mean,
                            'encrypt_std': encrypt_std,
                            'decrypt_mean': decrypt_mean,
                            'decrypt_std': decrypt_std,
                            'memory_mean': memory_mean,
                            'throughput': throughput,
                            'total_time': total_time
                        }
                        
                        # Add to summary table
                        self.summary_tree.insert('', 'end', values=(
                            algo_name,
                            f"{encrypt_mean:.4f} ± {encrypt_std:.4f}",
                            f"{decrypt_mean:.4f} ± {decrypt_std:.4f}",
                            f"{total_time:.4f}",
                            f"{throughput:.2f}",
                            f"{memory_mean:.2f}"
                        ))
                        
                        # Add to detailed results
                        self.advanced_results.insert(tk.END, 
                            f"      {algo_name} Results:\n"
                            f"      Encryption: {encrypt_mean:.4f}s (±{encrypt_std:.4f}s)\n"
                            f"      Decryption: {decrypt_mean:.4f}s (±{decrypt_std:.4f}s)\n"
                            f"      Total Time: {total_time:.4f}s\n"
                            f"      Throughput: {throughput:.2f} MB/s\n"
                            f"      Memory: {memory_mean:.2f} MB\n\n"
                        )
                    else:
                        self.advanced_results.insert(tk.END, f"    {algo_name}: No successful iterations\n\n")
                    
                    self.root.update()
                
                # Show overall results and recommendations
                self.display_benchmark_recommendations(benchmark_results)
                self.advanced_results.insert(tk.END, "\n Benchmark completed!\n")
                
                # Clean up sample file
                try:
                    if os.path.exists(sample_file):
                        os.remove(sample_file)
                except:
                    pass
                    
            except Exception as e:
                self.advanced_results.insert(tk.END, f"\n Error during benchmarking: {e}\n")
        
        threading.Thread(target=run_benchmark).start()    
        
    def run_security_scan(self):
        """Run security vulnerability scan"""
        try:
            algorithm = self.scan_algo_var.get()
            key_size = int(self.scan_key_var.get())
            mode = self.scan_mode_var.get() if self.scan_mode_var.get() != "None" else None
            
            report = self.vulnerability_scanner.generate_security_report(algorithm, key_size, mode)
            
            self.security_text.delete(1.0, tk.END)
            self.security_text.insert(tk.END, report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Security scan failed: {e}")
            
    def add_batch_files(self):
        """Add files to batch testing"""
        files = filedialog.askopenfilenames(title="Select files for batch testing")
        for file in files:
            self.file_listbox.insert(tk.END, file)
            
    def clear_batch_files(self):
        """Clear batch files list"""
        self.file_listbox.delete(0, tk.END)
        
    def run_batch_tests(self):
        """Run batch tests"""
        files = self.file_listbox.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "Please add files to test")
            return
            
        def run_batch():
            try:
                export_format = self.export_format.get()
                self.batch_tester.test_multiple_files(list(files), export_format)
                messagebox.showinfo("Success", f"Batch tests completed! Results exported as {export_format.upper()}")
            except Exception as e:
                messagebox.showerror("Error", f"Batch testing failed: {e}")
                
        threading.Thread(target=run_batch).start()
        
    def generate_chart(self):
        """Generate visualization chart"""
        try:
            chart_type = self.chart_type.get()
            
            # For demo purposes - you would use actual comparison data
            sample_data = {
                'AES-CBC': {'encryption_time': 0.025, 'decryption_time': 0.008, 'throughput_mbps': 0.38},
                'AES-GCM': {'encryption_time': 0.028, 'decryption_time': 0.009, 'throughput_mbps': 0.34},
                'ChaCha20': {'encryption_time': 0.001, 'decryption_time': 0.007, 'throughput_mbps': 1.08}
            }
            
            if chart_type == "performance":
                self.chart_generator.create_performance_chart(sample_data)
            else:
                self.chart_generator.create_throughput_chart(sample_data)
                
            self.chart_info.config(text=" Chart generated and displayed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Chart generation failed: {e}")
            
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.monitor_running = True
        self.real_time_monitor.start_monitoring()
        self.log_result(" Real-time monitoring started")
        
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitor_running = False
        self.real_time_monitor.stop_monitoring()
        self.log_result(" Real-time monitoring stopped")
        
    def update_monitor(self):
        """Update monitor display"""
        if self.monitor_running:
            # This would update with real metrics from RealTimeMonitor
            self.monitor_text.delete(1.0, tk.END)
            self.monitor_text.insert(tk.END, "CPU Usage: 45%\nMemory: 2.3GB\nOperations: 156")
            
        self.root.after(1000, self.update_monitor)  # Update every second
        
    def export_results(self):
        """Export results to file"""
        if not self.summary_tree.get_children():
            messagebox.showwarning("Warning", "No results to export. Please run a benchmark first.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]    )
        if filename:
            try:
                if filename.endswith('.csv'):
                    self.export_to_csv(filename)
                else:
                    self.export_to_txt(filename)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")

    def export_to_csv(self, filename):
        """Export results to CSV format"""
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['Algorithm', 'Encryption Time (s)', 'Decryption Time (s)', 
                            'Total Time (s)', 'Throughput (MB/s)', 'Memory Usage (MB)'])
                # Write data
            for item in self.summary_tree.get_children():
                values = self.summary_tree.item(item)['values']
                writer.writerow(values)

    def export_to_txt(self, filename):
        """Export results to text format"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Cryptography Algorithm Benchmark Results\n")
            f.write("=" * 50 + "\n\n")
            
            # Write summary table data
            f.write("SUMMARY RESULTS:\n")
            f.write("-" * 30 + "\n")
            for item in self.summary_tree.get_children():
                values = self.summary_tree.item(item)['values']
                f.write(f"{values[0]}: Encrypt={values[1]}, Decrypt={values[2]}, "
                    f"Total={values[3]}, Throughput={values[4]}, Memory={values[5]}\n")
            
            # Write detailed results
            f.write("\n\nDETAILED RESULTS:\n")
            f.write("-" * 30 + "\n")
            f.write(self.advanced_results.get(1.0, tk.END))   
                
    def log_result(self, message):
        """Log a message to results area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.results_text.see(tk.END)
        self.root.update()
    def clear_advanced_results(self):
        """Clear both summary and detailed results"""
        # Clear summary table
        for item in self.summary_tree.get_children():
            self.summary_tree.delete(item)
        
        # Clear detailed text
        self.advanced_results.delete(1.0, tk.END)

    def display_benchmark_recommendations(self, results):
        """Display recommendations based on benchmark results"""
        if not results:
            return
            
        self.advanced_results.insert(tk.END, "\n🎯 PERFORMANCE RECOMMENDATIONS\n")
        self.advanced_results.insert(tk.END, "=" * 50 + "\n")
        
        # Find best performers in different categories
        if results:
            # Fastest overall
            fastest = min(results.items(), key=lambda x: x[1]['total_time'])
            self.advanced_results.insert(tk.END, f"🏆 Fastest Overall: {fastest[0]} ({fastest[1]['total_time']:.4f}s)\n")
            
            # Highest throughput
            highest_throughput = max(results.items(), key=lambda x: x[1]['throughput'])
            self.advanced_results.insert(tk.END, f"📈 Highest Throughput: {highest_throughput[0]} ({highest_throughput[1]['throughput']:.2f} MB/s)\n")
            
            # Most memory efficient
            if any('memory_mean' in result for result in results.values()):
                most_efficient = min(results.items(), key=lambda x: x[1].get('memory_mean', float('inf')))
                self.advanced_results.insert(tk.END, f"💾 Most Memory Efficient: {most_efficient[0]} ({most_efficient[1].get('memory_mean', 0):.2f} MB)\n")
            
            # Performance differences
            self.advanced_results.insert(tk.END, "\n📊 Performance Differences:\n")
            fastest_time = fastest[1]['total_time']
            for algo_name, result in results.items():
                if algo_name != fastest[0]:
                    slowdown = ((result['total_time'] - fastest_time) / fastest_time) * 100
                    self.advanced_results.insert(tk.END, f"   {algo_name} is {slowdown:.1f}% slower than {fastest[0]}\n")
            
            # Use case recommendations
            self.advanced_results.insert(tk.END, "\n💡 Use Case Recommendations:\n")
            if 'ChaCha20' in results and results['ChaCha20']['total_time'] == fastest_time:
                self.advanced_results.insert(tk.END, "   • For maximum performance: Use ChaCha20\n")
            if 'AES-GCM' in results:
                self.advanced_results.insert(tk.END, "   • For authenticated encryption: Use AES-GCM\n")
            if 'AES-CBC' in results:
                self.advanced_results.insert(tk.END, "   • For compatibility: Use AES-CBC\n")
            if 'RSA' in results:
                self.advanced_results.insert(tk.END, "   • For key exchange: Use RSA with hybrid encryption\n")

        




    # Main application runner
def main():
    # Ensure data directory exists
    ensure_data_directory()
    
    # Create and run GUI
    root = tk.Tk()
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')  # Modern theme
    
    app = CryptoToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

def quick_compare(self):
    """Quick comparison of all algorithms including RSA"""
    if not self.current_file:
        messagebox.showwarning("Warning", "Please select a file first")
        return