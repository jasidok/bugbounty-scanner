#!/usr/bin/env python3
"""
Direct scan of Alchemix v2-foundry smart contracts
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import BugBountyScanner, ScanConfig, SmartContractScanner
from pathlib import Path
import json

def main():
    # Set up configuration
    config = ScanConfig(
        max_threads=4,
        delay_between_requests=0.5,
        timeout=30,
        rate_limit_per_second=2
    )
    
    # Initialize scanner
    scanner = BugBountyScanner(config)
    sc_scanner = SmartContractScanner(config)
    
    # Target directory
    target_dir = "bb_projects/v2-foundry"
    
    if not os.path.exists(target_dir):
        print(f"Directory {target_dir} not found!")
        return
    
    print(f"Scanning Alchemix v2-foundry contracts in {target_dir}...")
    
    # Scan directory recursively
    results = scanner._scan_directory_recursive(sc_scanner, target_dir)
    
    print(f"\nScan completed! Found {len(results)} potential vulnerabilities.")
    
    if results:
        print("\n=== SCAN RESULTS ===")
        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result.vulnerability_type}")
            print(f"   File: {result.target}")
            print(f"   Severity: {result.severity}")
            print(f"   Confidence: {result.confidence}")
            print(f"   Description: {result.description}")
            print(f"   Evidence: {result.evidence}")
            print(f"   Recommendations: {result.recommendations}")
            print(f"   Tool: {result.tool_used}")
    
    # Save results to JSON for further analysis
    results_data = []
    for result in results:
        results_data.append({
            "target": result.target,
            "vulnerability_type": result.vulnerability_type,
            "severity": result.severity,
            "description": result.description,
            "evidence": result.evidence,
            "recommendations": result.recommendations,
            "confidence": result.confidence,
            "tool_used": result.tool_used,
            "timestamp": result.timestamp.isoformat()
        })
    
    # Save to v2-foundry directory
    output_file = f"{target_dir}/alchemix_scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")

if __name__ == "__main__":
    main()