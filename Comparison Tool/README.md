Explore. Benchmark. Understand.

A Python GUI tool for students, developers, and crypto enthusiasts to explore and compare cryptographic algorithms interactively. The tool provides clear, visual insights into how different algorithms perform under varying conditions, making complex cryptography concepts easy to understand.

Key Features

GUI Interface: Built with Tkinter, featuring tabs for configuration, results, and visualization. Real-time input validation and progress indicators make testing smooth and intuitive.

Algorithm Support: Symmetric algorithms like AES (CBC/GCM) and ChaCha20, and asymmetric algorithms like RSA, ECC, DSA, ECDSA, and post-quantum Kyber.

Benchmarking & Visualization: Measure encryption, decryption, signing, verification, and key generation times with millisecond precision. Visualize results via interactive graphs, tables, and charts.

Flexible Testing: Configure key sizes, operation modes, elliptic curves, file types, and iteration counts. Supports single and batch file testing.

Export & Analysis: Save charts as high-resolution images, export results as JSON or CSV, and generate detailed performance reports.

Outcomes

This GUI helps users:

Understand algorithm performance across speed, memory usage, throughput, and success rates.

See trade-offs between security strength and operational efficiency.

Benchmark real-world scenarios for files of different sizes and types.

This tool provides a hands-on, visual approach to cryptography benchmarking, making it perfect for learning, research, and practical algorithm evaluation.

Setup Instructions

Clone the repository and navigate into it

git clone https://github.com/your-username/your-repo-name.git

cd cryptography-algo-visuals

Create a virtual environment

py -m venv venv

Activate the virtual environment

For PowerShell: .\venv\Scripts\Activate.ps1


Install required dependencies

pip install -r requirements.txt

Run the GUI

python launch_gui.py