#!/usr/bin/env python3
"""
Test script for enhanced smart contract scanner
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.smart_contract_verification import scan_directory_for_contracts
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    """Test the enhanced scanner on Noya contracts"""
    noya_dir = "bb_projects/noya-JUL-2025-audit-scope"
    
    if not os.path.exists(noya_dir):
        print(f"Error: {noya_dir} not found. Please clone the repository first.")
        return
    
    print(f"Testing enhanced scanner on {noya_dir}")
    print("=" * 60)
    
    # Scan with enhanced verification
    results = scan_directory_for_contracts(noya_dir)
    
    print(f"\n📊 ENHANCED SCANNER RESULTS")
    print("=" * 60)
    print(f"Total contracts scanned: {len(list(Path(noya_dir).rglob('*.sol')))}")
    print(f"Verified vulnerabilities found: {len(results)}")
    
    if results:
        # Group by vulnerability type
        vuln_types = {}
        for result in results:
            vuln_type = result['vulnerability_type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(result)
        
        print(f"\n🔍 VULNERABILITY BREAKDOWN:")
        for vuln_type, vulns in vuln_types.items():
            print(f"  {vuln_type}: {len(vulns)} findings")
        
        print(f"\n📋 DETAILED FINDINGS:")
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result['vulnerability_type']} ({result['severity']})")
            print(f"   File: {result['target']}")
            print(f"   Line: {result['line_number']}")
            print(f"   Description: {result['description']}")
            print(f"   Evidence: {result['evidence']}")
            print(f"   Confidence: {result['confidence']:.2f}")
            if 'verification' in result:
                verify = result['verification']
                print(f"   Verification: {verify.reason}")
    else:
        print("✅ No verified vulnerabilities found!")
        print("   This indicates either:")
        print("   - The contracts are secure")
        print("   - The enhanced scanner successfully filtered false positives")
    
    print("=" * 60)

if __name__ == "__main__":
    main()