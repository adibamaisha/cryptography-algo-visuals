#!/usr/bin/env python3
"""
Cryptography Tool GUI Launcher
"""

import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import tkinter
        import matplotlib
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install: tkinter, matplotlib")
        return False

def main():
    if not check_dependencies():
        sys.exit(1)
    
    try:
        from gui.main_window import main as gui_main
        print("🚀 Starting Cryptography Comparison Tool GUI...")
        gui_main()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        print("Make sure all modules are properly installed")
        sys.exit(1)

if __name__ == "__main__":
    main()