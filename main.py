# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 14:14:18 2025

@author: shook
"""

import sys
import os
import argparse
from gui import IDSGUI
import tkinter as tk
from ids_core import WindowsIDS

def main():
    parser = argparse.ArgumentParser(description='Windows Intrusion Detection System')
    parser.add_argument('--gui', action='store_true', help='Start with GUI interface')
    parser.add_argument('--console', action='store_true', help='Run in console mode')
    parser.add_argument('--service', action='store_true', help='Run as Windows service')
    
    args = parser.parse_args()
    
    if args.gui or (not args.console and not args.service):
        # Start GUI
        root = tk.Tk()
        app = IDSGUI(root)
        root.mainloop()
    
    elif args.console:
        # Console mode
        print("Starting Windows IDS in console mode...")
        ids = WindowsIDS()
        
        try:
            ids.start()
            print("IDS started. Press Ctrl+C to stop.")
            
            # Keep running
            import time
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping IDS...")
            ids.stop()
    
    elif args.service:
        # Service mode (simplified)
        print("Service mode would be implemented here")
        # This would integrate with pywin32 service framework

if __name__ == "__main__":
    main()