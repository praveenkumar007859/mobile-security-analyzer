"""
Report generator module for Static APK Security Auditor.
Merges findings from various security analysis modules and maps them to OWASP Mobile Top 10 categories.
"""

from typing import Dict, List
from collections import defaultdict
from tabulate import tabulate


# OWASP Mobile Top 10 Category Mapping
OWASP_CATEGORY_MAP = {
    "permissions": "Improper Platform Usage",
    "component": "Improper Platform Usage",
    "flag": "Insecure Communication",
    "secret": "Insufficient Cryptography",
}

# Finding type to OWASP category mapping based on finding keywords
FINDING_KEYWORD_MAP = {
    "dangerous": "Improper Platform Usage",
    "permission": "Improper Platform Usage",
    "exported": "Improper Platform Usage",
    "hardcoded": "Insufficient Cryptography",
    "secret": "Insufficient Cryptography",
    "api_key": "Insufficient Cryptography",
    "token": "Insufficient Cryptography",
    "password": "Insufficient Cryptography",
    "cleartext": "Insecure Communication",
    "http": "Insecure Communication",
    "unencrypted": "Insecure Communication",
    "traffic": "Insecure Communication",
}


def _map_to_owasp_category(finding_type: str, finding_text: str) -> str:
    """
    Map a finding to an OWASP Mobile Top 10 category.
    
    Args:
        finding_type: Type of finding ("permission", "component", "flag", "secret")
        finding_text: The finding description/text
        
    Returns:
        OWASP Mobile Top 10 category name
    """
    # First, check if finding_type has a direct mapping
    if finding_type in OWASP_CATEGORY_MAP:
        return OWASP_CATEGORY_MAP[finding_type]
    
    # Otherwise, search for keywords in the finding text
    finding_lower = finding_text.lower()
    for keyword, category in FINDING_KEYWORD_MAP.items():
        if keyword in finding_lower:
            return category
    
    # Default fallback
    return "Improper Platform Usage"


def generate_report(
    permission_findings: List[Dict],
    component_findings: List[Dict],
    flag_findings: List[Dict],
    secret_findings: List[Dict],
) -> Dict:
    """
    Generate a comprehensive security report from various finding types.
    
    Merges all findings into a structured report, maps each to OWASP Mobile Top 10 categories,
    and organizes them by severity and category.
    
    Args:
        permission_findings: List of permission-related findings
                            Each dict should have "permission" and "severity" keys
        component_findings: List of component-related findings
                           Each dict should have "component" and "severity" keys
        flag_findings: List of flag-related findings
                      Each dict should have "finding" and "severity" keys
        secret_findings: List of secret-related findings
                        Each dict should have "finding" and "severity" keys
    
    Returns:
        JSON-serializable dict with structure:
        {
            "summary": {
                "total_findings": int,
                "high_severity": int,
                "medium_severity": int,
                "low_severity": int
            },
            "findings_by_severity": {
                "High": [...],
                "Medium": [...],
                "Low": [...]
            },
            "findings_by_category": {
                "OWASP Category": [...]
            }
        }
    """
    # Combine all findings with their type metadata
    all_findings = []
    
    # Process permission findings
    for finding in permission_findings:
        all_findings.append({
            "type": "permission",
            "name": finding.get("permission", "Unknown Permission"),
            "severity": finding.get("severity", "Medium"),
            "owasp_category": _map_to_owasp_category("permission", finding.get("permission", "")),
        })
    
    # Process component findings
    for finding in component_findings:
        all_findings.append({
            "type": "component",
            "name": finding.get("component", "Unknown Component"),
            "severity": finding.get("severity", "Medium"),
            "owasp_category": _map_to_owasp_category("component", finding.get("component", "")),
        })
    
    # Process flag findings
    for finding in flag_findings:
        all_findings.append({
            "type": "flag",
            "name": finding.get("finding", "Unknown Flag"),
            "severity": finding.get("severity", "Medium"),
            "owasp_category": _map_to_owasp_category("flag", finding.get("finding", "")),
        })
    
    # Process secret findings
    for finding in secret_findings:
        all_findings.append({
            "type": "secret",
            "name": finding.get("finding", "Unknown Secret"),
            "severity": finding.get("severity", "Medium"),
            "owasp_category": _map_to_owasp_category("secret", finding.get("finding", "")),
        })
    
    # Count severity levels
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in all_findings:
        severity = finding.get("severity", "Medium")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Organize findings by severity
    findings_by_severity = {"High": [], "Medium": [], "Low": []}
    for finding in all_findings:
        severity = finding.get("severity", "Medium")
        if severity in findings_by_severity:
            findings_by_severity[severity].append(finding)
    
    # Organize findings by OWASP category
    findings_by_category = defaultdict(list)
    for finding in all_findings:
        category = finding.get("owasp_category", "Improper Platform Usage")
        findings_by_category[category].append(finding)
    
    # Build the report
    report = {
        "summary": {
            "total_findings": len(all_findings),
            "high_severity": severity_counts["High"],
            "medium_severity": severity_counts["Medium"],
            "low_severity": severity_counts["Low"],
        },
        "findings_by_severity": {
            severity: [
                {
                    "type": f.get("type"),
                    "name": f.get("name"),
                    "owasp_category": f.get("owasp_category"),
                }
                for f in findings
            ]
            for severity, findings in findings_by_severity.items()
        },
        "findings_by_category": {
            category: [
                {
                    "type": f.get("type"),
                    "name": f.get("name"),
                    "severity": f.get("severity"),
                }
                for f in findings
            ]
            for category, findings in findings_by_category.items()
        },
    }
    
    return report


def print_report(report: Dict) -> None:
    """
    Print a formatted console table of the security report.
    
    Displays findings grouped by severity, with columns for finding type,
    name, and OWASP Mobile Top 10 category.
    
    Args:
        report: JSON-serializable report dict from generate_report()
    """
    print("\n" + "=" * 80)
    print("STATIC APK SECURITY AUDIT REPORT")
    print("=" * 80 + "\n")
    
    # Print summary
    summary = report.get("summary", {})
    print("SUMMARY")
    print("-" * 80)
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    print(f"High Severity:  {summary.get('high_severity', 0)}")
    print(f"Medium Severity: {summary.get('medium_severity', 0)}")
    print(f"Low Severity:   {summary.get('low_severity', 0)}")
    print()
    
    # Print findings grouped by severity
    findings_by_severity = report.get("findings_by_severity", {})
    severity_order = ["High", "Medium", "Low"]
    
    for severity in severity_order:
        findings = findings_by_severity.get(severity, [])
        
        if not findings:
            continue
        
        print(f"\n{severity.upper()} SEVERITY FINDINGS")
        print("-" * 80)
        
        # Prepare table data
        table_data = []
        for finding in findings:
            table_data.append([
                finding.get("type", "N/A").upper(),
                finding.get("name", "N/A"),
                finding.get("owasp_category", "N/A"),
            ])
        
        # Print table
        headers = ["TYPE", "NAME", "OWASP CATEGORY"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Print findings by category
    findings_by_category = report.get("findings_by_category", {})
    
    if findings_by_category:
        print(f"\n\nFINDINGS BY OWASP MOBILE TOP 10 CATEGORY")
        print("-" * 80)
        
        for category in sorted(findings_by_category.keys()):
            findings = findings_by_category[category]
            print(f"\n{category}")
            print(f"  Count: {len(findings)}")
            
            # Prepare table data
            table_data = []
            for finding in findings:
                table_data.append([
                    finding.get("type", "N/A").upper(),
                    finding.get("name", "N/A"),
                    finding.get("severity", "N/A"),
                ])
            
            # Print table
            headers = ["TYPE", "NAME", "SEVERITY"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    print("\n" + "=" * 80 + "\n")
