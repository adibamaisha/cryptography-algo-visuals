Explore. Benchmark. Understand.

A Python GUI tool for students, developers, and crypto enthusiasts to explore and compare cryptographic algorithms interactively. The tool provides clear, visual insights into how different algorithms perform under varying conditions, making complex cryptography concepts easy to understand.

Key Features
============
GUI Interface: Built with Tkinter, featuring tabs for configuration, results, and visualization. Real-time input validation and progress indicators make testing smooth and intuitive.

Algorithm Support: Symmetric algorithms like AES (CBC/GCM) and ChaCha20, and asymmetric algorithms like RSA, ECC, DSA, ECDSA, and post-quantum Kyber.

Benchmarking & Visualization: Measure encryption, decryption, signing, verification, and key generation times with millisecond precision. Visualize results via interactive graphs, tables, and charts.

Flexible Testing: Configure key sizes, operation modes, elliptic curves, file types, and iteration counts. Supports single and batch file testing.

Export & Analysis: Save charts as high-resolution images, export results as JSON or CSV, and generate detailed performance reports.

Outcomes
============
This GUI helps users:

Understand algorithm performance across speed, memory usage, throughput, and success rates.

See trade-offs between security strength and operational efficiency.

Benchmark real-world scenarios for files of different sizes and types.

This tool provides a hands-on, visual approach to cryptography benchmarking, making it perfect for learning, research, and practical algorithm evaluation.

![Detailed Results](results/detailed_results.jpeg)
![Encryption Time Comparison](results/fileencryption_time_comparision.jpeg)
![Performance Comparison](results/fileperformance_comparision.jpeg)
![Results Table](results/results_table.jpeg)

Libraries Used
============
Tkinter – Builds the graphical user interface (GUI) for the tool; handles windows, buttons, tabs, forms, and interactive elements.

PyCryptodome – Provides the core implementations for cryptographic algorithms like AES, RSA, DSA, and ECC. Handles encryption, decryption, and key generation.

Cryptography – Adds extra cryptographic primitives and secure random number generation for stronger security.

Matplotlib – Creates the performance graphs and charts to visualize encryption/decryption speed, throughput, and algorithm comparisons.

NumPy – Performs numerical calculations, statistical analysis, and manages data for the charts.

Psutil – Tracks system resources such as CPU and memory usage during cryptographic operations.

Click – (If used) Helps with building command-line interfaces for scripts or additional features.

Rich – Generates fancy terminal outputs, tables, or live updates for real-time monitoring.

Setup Instructions
============
Clone the repository and navigate into it:
cd cryptography-algo-visuals

Create a virtual environment:
py -m venv venv

Activate the virtual environment:

PowerShell: .\venv\Scripts\Activate.ps1

Command Prompt: .\venv\Scripts\activate

Install required dependencies:
pip install -r requirements.txt

Run the GUI:
python launch_gui.py
