
import os
import argparse
import logging

# Import your three modules
import manifestparser
import secrets_scanner
# If your third file is named 'Untitled-3.py', we can alias it as 'generator'
try:
    import generator
except ImportError:
    import importlib
    generator = importlib.import_module("Untitled-3")

# Set up logging to prevent androguard cluttering terminal text
logging.basicConfig(level=logging.ERROR)

def run_pipeline(apk_path: str):
    if not os.path.exists(apk_path):
        print(f"[-] Error: Target APK file not found at: {apk_path}")
        return

    print(f"[*] Loading and analyzing APK: {os.path.basename(apk_path)}...")
    
    try:
        # 1. Initialize and load the APK using manifestparser
        apk_obj = manifestparser.load_apk(apk_path)
    except Exception as e:
        print(f"[-] Critical Error parsing APK: {e}")
        return

    # 2. Extract and Audit Manifest configuration
    print("[*] Auditing AndroidManifest.xml details...")
    raw_permissions = manifestparser.get_permissions(apk_obj)
    permission_findings = manifestparser.flag_dangerous_permissions(raw_permissions)
    component_findings = manifestparser.get_exported_components(apk_obj)
    
    # Extract structural configuration switches
    raw_flags = manifestparser.check_manifest_flags(apk_obj)
    
    # REMAPPING: The report module expects the key name to be 'finding', 
    # and we only want to report a flag if it was actually discovered ('found': True)
    flag_findings = []
    for flag_item in raw_flags:
        if flag_item.get("found"):
            flag_findings.append({
                "finding": f"Dangerous configuration switch enabled: {flag_item['flag']}",
                "severity": flag_item.get("severity", "High")
            })

    # 3. Run Source Code Strings Scanning
    print("[*] Passive source code analysis for credentials...")
    secret_findings = secrets_scanner.scan_for_secrets(apk_obj)

    # 4. Generate and Render Report Console Layout
    print("[*] Compiling analysis database to OWASP Top 10 categories...")
    
    # Process results into structured report payload
    report_payload = generator.generate_report(
        permission_findings=permission_findings,
        component_findings=component_findings,
        flag_findings=flag_findings,
        secret_findings=secret_findings
    )
    
    # Print the aggregated markdown/ASCII tables
    generator.print_report(report_payload)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static APK Security Testing Framework")
    parser.add_argument("apk", help="File system path pointing to the target .apk bundle")
    args = parser.parse_args()
    
    run_pipeline(args.apk)
