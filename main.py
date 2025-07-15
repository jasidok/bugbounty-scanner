#!/usr/bin/env python3
"""
Bug Bounty Scanner - Main Entry Point
Comprehensive security testing framework for bug bounty programs
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import main

if __name__ == "__main__":
    main()