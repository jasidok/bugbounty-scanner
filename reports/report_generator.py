"""
Advanced Reporting and Evidence Collection
Professional report generation with evidence management
"""

import io
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

class ReportGenerator:
    """Generate professional bug bounty reports"""
    
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.reports_dir = self.project_dir / 'reports'
        self.reports_dir.mkdir(exist_ok=True)
        
    def generate_executive_summary(self, results: List[Dict], program: Dict) -> str:
        """Generate executive summary with charts"""
        # Create severity distribution chart
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.get('severity', 'Unknown')] += 1
        
        # Generate chart
        plt.figure(figsize=(10, 6))
        severities = list(severity_counts.keys())
        counts = list(severity_counts.values())
        
        plt.subplot(1, 2, 1)
        plt.pie(counts, labels=severities, autopct='%1.1f%%')
        plt.title('Vulnerability Distribution by Severity')
        
        plt.subplot(1, 2, 2)
        plt.bar(severities, counts)
        plt.title('Vulnerability Count by Severity')
        plt.xticks(rotation=45)
        
        chart_path = self.reports_dir / 'severity_chart.png'
        plt.tight_layout()
        plt.savefig(chart_path)
        plt.close()
        
        # Generate executive summary
        summary = f"""
# Executive Summary - {program.get('name', 'Unknown Program')}

## Overview
This report presents the findings from a comprehensive security assessment of {program.get('name', 'Unknown Program')}.
The assessment was conducted using automated scanning tools and manual testing techniques.

## Key Statistics
- **Total Vulnerabilities**: {len(results)}
- **Critical**: {severity_counts.get('Critical', 0)}
- **High**: {severity_counts.get('High', 0)}
- **Medium**: {severity_counts.get('Medium', 0)}
- **Low**: {severity_counts.get('Low', 0)}
- **Informational**: {severity_counts.get('Info', 0)}

## Scope
The assessment covered the following targets:
{chr(10).join(f'- {scope}' for scope in program.get('scope', []))}

## Methodology
The security assessment employed multiple testing approaches:
- Static Analysis
- Dynamic Analysis
- Manual Testing
- Automated Vulnerability Scanning

## Risk Assessment
Based on the findings, the overall security posture requires attention, particularly in:
{self._generate_risk_assessment(results)}

## Recommendations
{self._generate_recommendations(results)}

## Next Steps
1. Prioritize remediation of Critical and High severity vulnerabilities
2. Implement security controls for identified weaknesses
3. Conduct follow-up testing after remediation
4. Establish ongoing security monitoring

---
*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        summary_file = self.reports_dir / 'executive_summary.md'
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        return str(summary_file)
    
    def generate_detailed_report(self, results: List[Dict], program: Dict) -> str:
        """Generate detailed technical report"""
        report_content = f"""
# Detailed Security Assessment Report
## {program.get('name', 'Unknown Program')}

### Program Information
- **Program Name**: {program.get('name', 'Unknown')}
- **Program URL**: {program.get('url', 'Unknown')}
- **Program Type**: {program.get('program_type', 'Unknown')}
- **Platform**: {program.get('platform', 'Unknown')}
- **Assessment Date**: {datetime.now().strftime('%Y-%m-%d')}

### Scope
The following assets were included in the assessment:
{chr(10).join(f'- {scope}' for scope in program.get('scope', []))}

### Out of Scope
The following assets were explicitly excluded:
{chr(10).join(f'- {oos}' for oos in program.get('out_of_scope', []))}

### Methodology
This assessment employed multiple testing techniques:
- **Automated Scanning**: Used industry-standard tools for vulnerability discovery
- **Manual Testing**: Conducted targeted testing of specific functionalities
- **Code Review**: Analyzed source code where available
- **Configuration Analysis**: Reviewed system and application configurations

### Findings Summary
A total of {len(results)} security findings were identified during the assessment.

"""
        
        # Group findings by severity
        findings_by_severity = defaultdict(list)
        for result in results:
            findings_by_severity[result.get('severity', 'Unknown')].append(result)
        
        # Generate detailed findings
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if severity in findings_by_severity:
                report_content += f"\n## {severity} Severity Findings\n\n"
                
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    report_content += self._generate_finding_detail(finding, i)
        
        # Add appendices
        report_content += self._generate_appendices(results, program)
        
        report_file = self.reports_dir / 'detailed_report.md'
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        return str(report_file)
    
    def _generate_finding_detail(self, finding: Dict, finding_number: int) -> str:
        """Generate detailed finding information"""
        return f"""
### Finding {finding_number}: {finding.get('vulnerability_type', 'Unknown')}

**Target**: {finding.get('target', 'Unknown')}
**Severity**: {finding.get('severity', 'Unknown')}
**Confidence**: {finding.get('confidence', 'Unknown')}
**Tool**: {finding.get('tool_used', 'Unknown')}
**Discovered**: {finding.get('timestamp', 'Unknown')}

#### Description
{finding.get('description', 'No description available')}

#### Evidence
{finding.get('evidence', 'No evidence available')}

#### Impact
{self._get_impact_description(finding.get('severity', 'Unknown'), finding.get('vulnerability_type', 'Unknown'))}

#### Remediation
{finding.get('recommendations', 'No recommendations available')}

#### References
{self._get_references(finding.get('vulnerability_type', 'Unknown'))}

---

"""
    
    def _get_impact_description(self, severity: str, vuln_type: str) -> str:
        """Get detailed impact description"""
        impact_templates = {
            'Critical': {
                'SQL Injection': 'This vulnerability could allow attackers to execute arbitrary SQL commands, potentially leading to complete database compromise, data theft, or system takeover.',
                'Remote Code Execution': 'This vulnerability could allow attackers to execute arbitrary code on the server, leading to complete system compromise.',
                'default': 'This critical vulnerability could lead to complete system compromise and should be addressed immediately.'
            },
            'High': {
                'Cross-Site Scripting (XSS)': 'This vulnerability could allow attackers to execute malicious scripts in users\' browsers, potentially stealing session cookies or performing actions on behalf of users.',
                'Authentication Bypass': 'This vulnerability could allow attackers to bypass authentication mechanisms and gain unauthorized access to sensitive areas.',
                'default': 'This high-severity vulnerability could lead to significant security compromise and should be prioritized for remediation.'
            },
            'Medium': {
                'Information Disclosure': 'This vulnerability could expose sensitive information to unauthorized users, potentially aiding in further attacks.',
                'default': 'This medium-severity vulnerability could contribute to security compromise and should be addressed in the next security update cycle.'
            },
            'Low': {
                'default': 'This low-severity vulnerability has minimal immediate impact but should be addressed as part of routine security maintenance.'
            },
            'Info': {
                'default': 'This informational finding does not represent an immediate security risk but may be useful for improving overall security posture.'
            }
        }
        
        return impact_templates.get(severity, {}).get(vuln_type, 
            impact_templates.get(severity, {}).get('default', 'Impact assessment required.'))
    
    def _get_references(self, vuln_type: str) -> str:
        """Get references for vulnerability type"""
        references = {
            'SQL Injection': [
                'OWASP SQL Injection Prevention Cheat Sheet',
                'CWE-89: SQL Injection',
                'NIST SP 800-53: SI-10 Information Input Validation'
            ],
            'Cross-Site Scripting (XSS)': [
                'OWASP XSS Prevention Cheat Sheet',
                'CWE-79: Cross-site Scripting',
                'OWASP Top 10 2021 - A03 Injection'
            ],
            'Open Redirect': [
                'OWASP Unvalidated Redirects and Forwards Cheat Sheet',
                'CWE-601: URL Redirection to Untrusted Site'
            ]
        }
        
        refs = references.get(vuln_type, ['Generic security references available'])
        return '\n'.join(f'- {ref}' for ref in refs)
    
    def _generate_risk_assessment(self, results: List[Dict]) -> str:
        """Generate risk assessment summary"""
        critical_count = sum(1 for r in results if r.get('severity') == 'Critical')
        high_count = sum(1 for r in results if r.get('severity') == 'High')
        
        if critical_count > 0:
            return f"- **Critical Risk**: {critical_count} critical vulnerabilities require immediate attention"
        elif high_count > 0:
            return f"- **High Risk**: {high_count} high-severity vulnerabilities need prompt remediation"
        else:
            return "- **Moderate Risk**: No critical or high-severity vulnerabilities identified"
    
    def _generate_recommendations(self, results: List[Dict]) -> str:
        """Generate consolidated recommendations"""
        recommendations = set()
        for result in results:
            recommendations.add(result.get('recommendations', 'No recommendations available'))
        
        return '\n'.join(f'- {rec}' for rec in sorted(recommendations))
    
    def _generate_appendices(self, results: List[Dict], program: Dict) -> str:
        """Generate report appendices"""
        return f"""
## Appendices

### Appendix A: Testing Tools Used
The following tools were used during the assessment:
{chr(10).join(f'- {tool}' for tool in set(r.get('tool_used', 'Unknown') for r in results))}

### Appendix B: Vulnerability Classification
Vulnerabilities are classified using the following severity levels:
- **Critical**: Vulnerabilities that could lead to complete system compromise
- **High**: Vulnerabilities that could lead to significant security impact
- **Medium**: Vulnerabilities with moderate security impact
- **Low**: Vulnerabilities with minimal security impact
- **Informational**: Findings that may improve security posture

### Appendix C: Scope Documentation
**In Scope:**
{chr(10).join(f'- {scope}' for scope in program.get('scope', []))}

**Out of Scope:**
{chr(10).join(f'- {oos}' for oos in program.get('out_of_scope', []))}

### Appendix D: Testing Methodology
1. **Reconnaissance**: Gathered information about target systems
2. **Vulnerability Discovery**: Used automated tools to identify potential issues
3. **Manual Testing**: Conducted targeted testing of identified areas
4. **Validation**: Confirmed vulnerabilities and assessed their impact
5. **Documentation**: Recorded findings with evidence and recommendations

### Appendix E: Disclaimer
This security assessment was conducted using automated tools and manual testing techniques. While comprehensive, it may not identify all possible vulnerabilities. The assessment is based on the system state at the time of testing and should be considered a snapshot of the security posture.
"""
    
    def generate_pdf_report(self, results: List[Dict], program: Dict) -> str:
        """Generate PDF report using ReportLab"""
        pdf_file = self.reports_dir / f"{program.get('name', 'Unknown')}_security_report.pdf"
        
        doc = SimpleDocTemplate(str(pdf_file), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph(f"Security Assessment Report<br/>{program.get('name', 'Unknown')}", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        # Findings table
        findings_data = [['Severity', 'Count', 'Percentage']]
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.get('severity', 'Unknown')] += 1
        
        total_findings = len(results)
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(severity, 0)
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            findings_data.append([severity, str(count), f"{percentage:.1f}%"])
        
        findings_table = Table(findings_data)
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 20))
        
        # Detailed findings
        story.append(Paragraph("Detailed Findings", styles['Heading2']))
        
        for i, result in enumerate(results, 1):
            story.append(Paragraph(f"Finding {i}: {result.get('vulnerability_type', 'Unknown')}", styles['Heading3']))
            story.append(Paragraph(f"<b>Target:</b> {result.get('target', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"<b>Severity:</b> {result.get('severity', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"<b>Description:</b> {result.get('description', 'No description')}", styles['Normal']))
            story.append(Paragraph(f"<b>Recommendation:</b> {result.get('recommendations', 'No recommendations')}", styles['Normal']))
            story.append(Spacer(1, 12))
        
        doc.build(story)
        return str(pdf_file)