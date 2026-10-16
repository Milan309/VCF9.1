#!/usr/bin/env python3
"""
Bulk certificate report generator for VCF Operations 9.1.

What it does:
  - Connects to VCF Operations and authenticates.
  - Queries all managed certificates (paginated, de-duplicated).
  - Aborts WITHOUT saving if the retrieval is incomplete.
  - Saves the raw certificate list to 'certificates_report.json'
    (same 'vcfCertificateModels' structure the bulk CSR script expects,
    plus 'generatedAt' and 'source' metadata fields).
  - Prints a summary table (sorted by days to expiry) and a count by category/type.

Usage:
  Interactive:      python3 GenerateReport.py
  Non-interactive:  VCF_OPS_PASSWORD='...' python3 GenerateReport.py \
                        --fqdn ops-a.site-a.vcf.lab --user admin
  Optional flags:   --output <file>   --ca-bundle <path to CA bundle>

TLS note: by default SSL verification is DISABLED (lab use). Pass --ca-bundle
with your CA bundle path to enable verification in production.
"""

import argparse
import getpass
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
PAGE_SIZE = 500
DEFAULT_OUTPUT = "certificates_report.json"


# ==========================================
# FUNCTIONS
# ==========================================

def get_auth_token(session, fqdn, user, password):
    """Get an authentication token from VCF Operations."""
    url = f"https://{fqdn}/suite-api/api/auth/token/acquire"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"username": user, "password": password}
    try:
        r = session.post(url, headers=headers, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        token = r.json().get("token")
        if not token:
            print("[-] Error: no token received.")
            return None
        print("[+] Token obtained successfully.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"[-] Authentication error: {e}")
        return None


def release_token(session, fqdn, token):
    """Release the token at the end (best effort, errors are ignored)."""
    url = f"https://{fqdn}/suite-api/api/auth/token/release"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        session.post(url, headers=headers, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        pass


def get_all_certificates(session, fqdn, token):
    """
    Query all certificates using pagination.
    Returns a de-duplicated list, or None if the retrieval was incomplete.
    """
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/certificates/query"
    headers = {
        "Authorization": f"OpsToken {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    certs_by_id = {}
    page = 0
    total = None

    while True:
        payload = {"pageSize": PAGE_SIZE, "page": page}
        try:
            r = session.post(url, headers=headers, json=payload, timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json()
        except requests.exceptions.RequestException as e:
            print(f"[-] Error querying certificates on page {page}: {e}")
            if getattr(e, "response", None) is not None:
                print(f"    Detail: {e.response.text}")
            return None

        batch = data.get("vcfCertificateModels", [])
        total = (data.get("pageInfo") or {}).get("totalCount", total)

        new_items = 0
        for cert in batch:
            key = cert.get("certificateResourceKey") or json.dumps(cert, sort_keys=True)
            if key not in certs_by_id:
                certs_by_id[key] = cert
                new_items += 1

        shown_total = total if total is not None else len(certs_by_id)
        print(f"    -> Retrieved {len(certs_by_id)}/{shown_total} certificates...")

        # Stop when the page is empty, nothing new arrived (server ignoring 'page'),
        # or we already have everything.
        if not batch or new_items == 0:
            break
        if total is not None and len(certs_by_id) >= total:
            break
        page += 1

    certificates = list(certs_by_id.values())
    if total is not None and len(certificates) < total:
        print(f"[-] Incomplete retrieval: got {len(certificates)} of {total} certificates.")
        return None
    return certificates


def sort_key(cert):
    """Sort by days to expiry (ascending); entries without a value go last."""
    days = cert.get("daysToExpire")
    return (days is None, days if days is not None else 0)


def print_summary_table(certificates):
    """Print a summary table (sorted by days to expiry) and counts by category/type."""
    if not certificates:
        print("[!] No certificates found.")
        return

    width = 175
    print("\n" + "=" * width)
    print(f"{'Certificate ID (Resource Key)':<38} {'Component':<22} {'FQDN':<36} "
          f"{'Category':<14} {'Type':<12} {'Days left':>9}  {'Status':<12}")
    print("=" * width)

    for cert in sorted(certificates, key=sort_key):
        cert_id = cert.get("certificateResourceKey") or "N/A"
        appliance = cert.get("appliance") or "N/A"
        fqdn = cert.get("applianceFqdn") or "N/A"
        category = cert.get("category") or "N/A"
        ctype = cert.get("type") or "N/A"
        days = cert.get("daysToExpire")
        days_txt = str(days) if days is not None else "N/A"
        status = cert.get("displayStatus") or "N/A"

        print(f"{cert_id:<38} {appliance:<22} {fqdn:<36} "
              f"{category:<14} {ctype:<12} {days_txt:>9}  {status:<12}")

    print("=" * width)
    print(f"Total certificates: {len(certificates)}")

    counts = Counter((c.get("category") or "N/A", c.get("type") or "N/A") for c in certificates)
    print("\nBy category / type:")
    for (category, ctype), n in sorted(counts.items()):
        print(f"  {category:<16} {ctype:<14} {n}")
    print("=" * width + "\n")


# ==========================================
# MAIN
# ==========================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a certificate report from VCF Operations 9.1 "
                    "(input for the bulk CSR generation script)."
    )
    parser.add_argument("--fqdn", help="VCF Operations FQDN")
    parser.add_argument("--user", help="Username (e.g. admin)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--ca-bundle",
                        help="Path to a CA bundle to enable TLS verification "
                             "(default: verification disabled, lab use)")
    return parser.parse_args()


def main():
    args = parse_args()

    print("\n[*] VCF Operations connection settings")
    fqdn = args.fqdn or input("  VCF Operations FQDN: ").strip()
    user = args.user or input("  Username (e.g. admin): ").strip()
    password = os.environ.get("VCF_OPS_PASSWORD") or getpass.getpass("  Password: ")

    session = requests.Session()
    if args.ca_bundle:
        session.verify = args.ca_bundle
    else:
        session.verify = False
        print("[!] TLS verification is disabled (use --ca-bundle to enable it).")

    token = get_auth_token(session, fqdn, user, password)
    if not token:
        print("[-] Could not authenticate. Exiting.")
        sys.exit(1)

    try:
        print("[*] Querying certificates from VCF Operations...")
        certificates = get_all_certificates(session, fqdn, token)

        if certificates is None:
            print("[-] Retrieval failed or was incomplete; report NOT saved.")
            sys.exit(1)
        if not certificates:
            print("[-] No certificates retrieved. Check your permissions or environment.")
            sys.exit(1)

        print_summary_table(certificates)

        output_data = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "source": fqdn,
            "vcfCertificateModels": certificates,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        print(f"[+] Full report saved to '{args.output}'")
        print("[*] You can now run the bulk CSR generation script using this file.")
    finally:
        release_token(session, fqdn, token)


if __name__ == "__main__":
    main()