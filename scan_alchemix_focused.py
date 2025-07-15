#!/usr/bin/env python3
"""
Focused scan of Alchemix v2-foundry smart contracts
Excludes external/aave, mocks, and test folders
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import BugBountyScanner, ScanConfig, SmartContractScanner
from pathlib import Path
import json

def find_solidity_files(directory, exclude_dirs=None):
    """Find all .sol files excluding specified directories"""
    if exclude_dirs is None:
        exclude_dirs = []
    
    sol_files = []
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories from the search
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        # Check if current path contains any excluded directory
        should_skip = False
        for exclude_dir in exclude_dirs:
            if exclude_dir in root:
                should_skip = True
                break
        
        if should_skip:
            continue
            
        for file in files:
            if file.endswith('.sol'):
                sol_files.append(os.path.join(root, file))
    
    return sol_files

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
    target_dir = "bb_projects/v2-foundry/src"
    
    # Excluded directories
    exclude_dirs = ["external/aave", "mocks", "test"]
    
    if not os.path.exists(target_dir):
        print(f"Directory {target_dir} not found!")
        return
    
    print(f"Scanning Alchemix v2-foundry src/ directory...")
    print(f"Excluding: {', '.join(exclude_dirs)}")
    
    # Find all .sol files excluding specified directories
    sol_files = find_solidity_files(target_dir, exclude_dirs)
    
    print(f"Found {len(sol_files)} Solidity files to scan")
    
    # Scan each file
    results = []
    for sol_file in sol_files:
        try:
            file_results = sc_scanner.scan_solidity_file(sol_file)
            results.extend(file_results)
            print(f"Scanned {sol_file}: {len(file_results)} findings")
        except Exception as e:
            print(f"Error scanning {sol_file}: {e}")
    
    print(f"\nFocused scan completed! Found {len(results)} potential vulnerabilities.")
    
    # Group results by severity
    severity_counts = {}
    for result in results:
        severity = result.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nSeverity breakdown:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    # Group by vulnerability type
    vuln_types = {}
    for result in results:
        vuln_type = result.vulnerability_type
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    print("\nVulnerability types:")
    for vuln_type, count in sorted(vuln_types.items()):
        print(f"  {vuln_type}: {count}")
    
    # Save results to JSON
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
    output_file = "bb_projects/v2-foundry/alchemix_focused_scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    # Show files scanned
    print(f"\nFiles scanned ({len(sol_files)}):")
    for sol_file in sorted(sol_files):
        print(f"  {sol_file}")

if __name__ == "__main__":
    main()