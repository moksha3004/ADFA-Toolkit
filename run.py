#!/usr/bin/env python3
"""
Advanced Digital Forensics & Anti-Forensics Detection Toolkit
Web Server Startup Script

Run with: python3 run.py
Then open: http://localhost:5050
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from app import app

if __name__ == '__main__':
    print()
    print('  ╔══════════════════════════════════════════════════════╗')
    print('  ║  Advanced Digital Forensics & Anti-Forensics Toolkit ║')
    print('  ╠══════════════════════════════════════════════════════╣')
    print('  ║  Open in browser: http://localhost:5050              ║')
    print('  ║  Press Ctrl+C to stop                               ║')
    print('  ╚══════════════════════════════════════════════════════╝')
    print()
    app.run(host='0.0.0.0', port=5050, debug=False)
