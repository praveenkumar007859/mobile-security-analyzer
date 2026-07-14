"""
main.py
Integration entry point - Mobile Application Security Analyser.
Run: python main.py [apk_path] [--format json]
"""
import json
import argparse
import logging
logging.getLogger("androguard").setLevel(logging.CRITICAL)

from manifestparser import (
    load_apk, get_permissions, flag_dangerous_permissions,
    get_exported_components, check_manifest_flags, check_min_sdk_version
)
from secrets_scanner import scan_for_secrets, scan_for_weak_crypto, scan_for_cleartext_urls
from report_generator import generate_report, print_report, generate_html_report


def main():
    # 1. Set up argparse to handle command-line inputs professionally
    parser = argparse.ArgumentParser(description="Static APK Security Testing Framework")
    parser.add_argument("apk", help="File system path pointing to the target .apk bundle")
    parser.add_argument("--format", choices=['table', 'json'], default='table', help="Choose the output format")
    args = parser.parse_args()

    apk_path = args.apk

    print(f"\nLoading APK: {apk_path} ...")
    apk_obj = load_apk(apk_path)

    print("Parsing manifest and permissions...")
    permission_findings = flag_dangerous_permissions(get_permissions(apk_obj))
    component_findings = get_exported_components(apk_obj)
    flag_findings = check_manifest_flags(apk_obj)
    sdk_findings = check_min_sdk_version(apk_obj)

    print("Scanning code and resources for hardcoded secrets...")
    secret_findings = scan_for_secrets(apk_obj)

    print("Scanning for weak cryptographic algorithms...")
    crypto_findings = scan_for_weak_crypto(apk_obj)

    print("Scanning for hardcoded cleartext URLs...")
    url_findings = scan_for_cleartext_urls(apk_obj)

    # 2. Generate the central report dictionary
    report = generate_report(
        permission_findings, component_findings, flag_findings,
        sdk_findings, secret_findings, crypto_findings, url_findings
    )

    # 3. Check the format flag and print accordingly
    if args.format == 'json':
        print("\n--- JSON OUTPUT ---")
        print(json.dumps(report, indent=4))
    else:
        print_report(report)

    generate_html_report(report)


if __name__ == "__main__":
    main()
