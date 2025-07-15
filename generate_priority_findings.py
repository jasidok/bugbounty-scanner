#!/usr/bin/env python3
"""
Generate prioritized list of legitimate security findings
"""

import json
import os
from collections import defaultdict

def load_false_positive_analysis():
    """Load the false positive analysis results"""
    with open("bb_projects/v2-foundry/false_positive_analysis.json", 'r') as f:
        return json.load(f)

def generate_priority_findings():
    """Generate prioritized list of legitimate findings"""
    
    analysis = load_false_positive_analysis()
    
    # Extract legitimate issues
    legitimate_issues = []
    
    for vuln_type, data in analysis.items():
        for issue in data['details']['legitimate_issues']:
            issue['vulnerability_type'] = vuln_type
            legitimate_issues.append(issue)
    
    # Sort by severity and confidence
    def priority_score(issue):
        severity_weights = {'High': 3, 'Medium': 2, 'Low': 1}
        confidence_score = float(issue['confidence'].split('(')[1].split(')')[0].replace('Verified: ', ''))
        return severity_weights.get(issue['severity'], 0) * confidence_score
    
    legitimate_issues.sort(key=priority_score, reverse=True)
    
    # Group by file
    by_file = defaultdict(list)
    for issue in legitimate_issues:
        file_name = issue['target'].split('/')[-1]
        by_file[file_name].append(issue)
    
    # Generate report
    report = """# Priority Security Findings - Alchemix v2-foundry

## Executive Summary

After filtering out false positives, **{total_legitimate}** legitimate security findings remain that require manual review. These have been prioritized by severity and confidence level.

## Priority Findings by Severity

### High Priority (High Severity)
""".format(total_legitimate=len(legitimate_issues))
    
    high_priority = [i for i in legitimate_issues if i['severity'] == 'High']
    medium_priority = [i for i in legitimate_issues if i['severity'] == 'Medium']
    
    if high_priority:
        report += f"\n**{len(high_priority)} High Severity Issues Found**\n\n"
        for i, issue in enumerate(high_priority[:20], 1):  # Top 20 high severity
            report += f"{i}. **{issue['vulnerability_type']}** in `{issue['target'].split('/')[-1]}`\n"
            report += f"   - Line: {issue['description'].split('line ')[-1] if 'line ' in issue['description'] else 'N/A'}\n"
            report += f"   - Evidence: {issue['evidence'][:100]}...\n"
            report += f"   - Confidence: {issue['confidence']}\n\n"
    
    report += f"\n### Medium Priority (Medium Severity)\n\n**{len(medium_priority)} Medium Severity Issues Found**\n\n"
    
    for i, issue in enumerate(medium_priority[:15], 1):  # Top 15 medium severity
        report += f"{i}. **{issue['vulnerability_type']}** in `{issue['target'].split('/')[-1]}`\n"
        report += f"   - Evidence: {issue['evidence'][:80]}...\n\n"
    
    # Files with most issues
    report += "\n## Files Requiring Most Attention\n\n"
    sorted_files = sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True)
    
    for file_name, issues in sorted_files[:10]:
        report += f"- **{file_name}**: {len(issues)} issues\n"
        high_count = len([i for i in issues if i['severity'] == 'High'])
        medium_count = len([i for i in issues if i['severity'] == 'Medium'])
        report += f"  - High: {high_count}, Medium: {medium_count}\n"
    
    # Specific recommendations
    report += """
## Specific Recommendations

### Access Control Issues
The majority of legitimate findings are missing access control issues. Focus on:
1. Functions that modify state without proper access modifiers
2. External functions accessible by any address
3. Critical administrative functions

### Fund Loss Vulnerabilities  
Review transfer and withdrawal functions for:
1. Proper validation of amounts and recipients
2. Reentrancy protection
3. Use of SafeERC20 for token transfers

### Manual Review Process
1. **Priority 1**: Review all High severity findings first
2. **Priority 2**: Focus on core contracts (AlchemistV2, Asset Managers)
3. **Priority 3**: Review interface and adapter contracts
4. **Testing**: Ensure comprehensive test coverage for flagged functions

## Next Steps

1. Assign security team to review the {high_count} high-severity issues
2. Implement additional access controls where needed
3. Add comprehensive testing for identified functions
4. Consider professional security audit for critical findings
""".format(high_count=len(high_priority))
    
    return report

def main():
    """Main function"""
    if not os.path.exists("bb_projects/v2-foundry/false_positive_analysis.json"):
        print("False positive analysis file not found. Run analyze_false_positives.py first.")
        return
    
    print("Generating priority findings report...")
    
    report = generate_priority_findings()
    
    # Save report
    with open("bb_projects/v2-foundry/PRIORITY_FINDINGS.md", 'w') as f:
        f.write(report)
    
    print("Priority findings report saved to: bb_projects/v2-foundry/PRIORITY_FINDINGS.md")

if __name__ == "__main__":
    main()