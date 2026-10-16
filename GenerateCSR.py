#!/usr/bin/env python3
"""
Bulk CSR generator for VCF Operations 9.1 (Fleet Management > Certificates).

What it does:
  - Reads certificates_report.json (output of the certificate report script).
  - Excludes ROOT_CERT entries (VMCA root CAs do not support CSR generation).
  - Takes default subject values (C, O, OU, L, ST, email) from the first
    certificate and lets the user override them.
  - Sends commonName (required by the API) and SANs (dns/ip) per component.
  - Waits for the workflow to finish, then fetches the CSR from the CSR list
    (paginated, matched by commonName / applianceHostname).
  - Normalizes the CSR to valid PEM (64 chars per line) before saving it.

Output: one .csr file per component in ./csrs_generated/

Notes:
  - The private key stays in the VCF Operations keystore. Do NOT regenerate a
    CSR after submitting it to your CA: it overwrites the stored private key.
  - SSL verification is disabled (lab use). Adjust for production.
"""

import requests
import json
import os
import re
import getpass
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
VALID_KEY_SIZES = ["KEY_2048", "KEY_3072", "KEY_4096"]
SKIP_CATEGORIES = {"ROOT_CERT"}   # categories that do not support CSR generation
CERT_REPORT_FILE = "certificates_report.json"
CSR_OUTPUT_DIR = "csrs_generated"


# ==========================================
# FUNCTIONS
# ==========================================

def get_auth_token(fqdn, user, password):
    """Get an authentication token from VCF Operations."""
    url = f"https://{fqdn}/suite-api/api/auth/token/acquire"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"username": user, "password": password}
    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=TIMEOUT)
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


def get_certificate_details(fqdn, token, certificate_id):
    """Get details of a specific certificate."""
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/certificates/{certificate_id}"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error getting details for {certificate_id}: {e}")
        return None


def parse_dn(dn_string):
    """Parse a Distinguished Name, splitting on commas that are not escaped or quoted."""
    result = {}
    parts, buf, in_quotes, escape = [], "", False, False
    for ch in dn_string or "":
        if escape:
            buf += ch
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf:
        parts.append(buf)
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            result[key.strip()] = value.strip()
    # The email attribute can show up as a raw OID
    if "emailAddress" not in result and "1.2.840.113549.1.9.1" in result:
        result["emailAddress"] = result["1.2.840.113549.1.9.1"]
    return result


def extract_csr_defaults(cert_details):
    """Extract default CSR subject values from a certificate."""
    dn = parse_dn(cert_details.get("issuedTo", ""))
    return {
        "country": dn.get("C", ""),
        "organization": dn.get("O", ""),
        "orgUnit": dn.get("OU", ""),
        "locality": dn.get("L", ""),
        "state": dn.get("ST", ""),
        "email": dn.get("emailAddress", ""),
    }


def prompt_for_csr_spec(defaults):
    """Show defaults, let the user override them, and return the final CSR spec."""
    print("\n" + "=" * 80)
    print("DEFAULT CSR VALUES (extracted from the first certificate)")
    print("=" * 80)
    for key, value in defaults.items():
        print(f"  {key:<15}: {value}")
    print("=" * 80)

    key_size = "KEY_2048"
    key_algorithm = "RSA"

    choice = input("\nDo you want to replace these values for all components? (y/N): ").strip().lower()
    if choice in ("y", "yes"):
        print("\nEnter new values (leave blank to keep the current one):")
        new_defaults = {}
        for key, value in defaults.items():
            user_input = input(f"  {key} [{value}]: ").strip()
            new_defaults[key] = user_input if user_input else value
        defaults = new_defaults

        print("\n  Key parameters:")
        user_key_size = input(f"    keySize {VALID_KEY_SIZES} [{key_size}]: ").strip()
        if user_key_size:
            key_size = user_key_size
        user_key_algorithm = input(f"    keyAlgorithm [{key_algorithm}]: ").strip()
        if user_key_algorithm:
            key_algorithm = user_key_algorithm
    else:
        print("[*] Using the values extracted from the certificate.")

    if key_size not in VALID_KEY_SIZES:
        print(f"[!] keySize '{key_size}' is not in {VALID_KEY_SIZES}; using KEY_2048.")
        key_size = "KEY_2048"

    # organization and orgUnit are required by the API
    for req in ("organization", "orgUnit"):
        while not defaults.get(req):
            defaults[req] = input(f"  '{req}' is required, please enter a value: ").strip()

    csr_spec = {
        "country": defaults.get("country", ""),
        "organization": defaults.get("organization", ""),
        "orgUnit": defaults.get("orgUnit", ""),
        "locality": defaults.get("locality", ""),
        "state": defaults.get("state", ""),
        "email": defaults.get("email", ""),
        "keySize": key_size,
        "keyAlgorithm": key_algorithm,
    }
    # Drop empty optional values so empty strings are not sent
    csr_spec = {k: v for k, v in csr_spec.items() if v}

    print("\n[*] Final CSR specification:")
    for k, v in csr_spec.items():
        print(f"    {k}: {v}")
    return csr_spec


def build_csr_payload(cert, csr_spec):
    """Build the POST body, including commonName (required) and SANs."""
    cn = cert.get("applianceFqdn")
    cert_id = cert.get("certificateResourceKey")
    if not cn or not cert_id:
        return None

    san = cert.get("subjectAlternativeNames") or {}
    dns = list(san.get("dns") or [])
    ip = list(san.get("ip") or [])
    if cn not in dns:              # the CN must always be present in the DNS SANs
        dns.insert(0, cn)

    spec = {**csr_spec, "commonName": cn,
            "subjectAltNames": {"dns": dns, "ip": ip}}
    return {"certificateId": cert_id, "generateCsrSpec": spec}


def generate_csr(fqdn, token, payload):
    """Launch the CSR generation workflow for one certificate."""
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/csrs"
    headers = {
        "Authorization": f"OpsToken {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error generating CSR: {e}")
        if getattr(e, "response", None) is not None:
            print(f"    Detail: {e.response.text}")
        return None


def get_workflow_status(fqdn, token, request_id):
    """Check the status of a workflow request."""
    url = f"https://{fqdn}/suite-api/api/workflows/requests/{request_id}"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error checking request {request_id}: {e}")
        return None


def get_generated_csr(fqdn, token, common_name):
    """
    List all CSRs (paginated) and pick the one matching the component FQDN.
    The server does not filter reliably by certificateId, so matching is done
    client-side on commonName / applianceHostname.
    Returns (csr_text_or_None, all_items).
    """
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/csrs"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    items, page = [], 0
    while True:
        params = {"page": page, "pageSize": 100}
        try:
            r = requests.get(url, headers=headers, params=params, verify=False, timeout=TIMEOUT)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching CSRs: {e}")
            return None, items
        data = r.json()
        batch = data.get("certificateSignatureInfo", [])
        items.extend(batch)
        total = (data.get("pageInfo") or {}).get("totalCount", len(items))
        if not batch or len(items) >= total:
            break
        page += 1

    cn = (common_name or "").lower()
    exact = [i for i in items if (i.get("commonName") or "").lower() == cn]
    by_host = [i for i in items if (i.get("applianceHostname") or "").lower() == cn]
    pick = exact or by_host
    if pick:
        return pick[-1].get("csr"), items
    return None, items


def normalize_pem(csr):
    """Convert the CSR (returned space-separated) into valid PEM, 64 chars per line."""
    body = re.sub(r"-----(BEGIN|END) CERTIFICATE REQUEST-----", "", csr)
    body = "".join(body.split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE REQUEST-----\n"
            + "\n".join(lines)
            + "\n-----END CERTIFICATE REQUEST-----\n")


# ==========================================
# MAIN
# ==========================================

def main():
    print("\n[*] VCF Operations connection settings")
    VCF_OPS_FQDN = input("  VCF Operations FQDN: ").strip()
    VCF_OPS_USER = input("  Username (e.g. admin): ").strip()
    VCF_OPS_PASS = getpass.getpass("  Password: ")

    if not os.path.exists(CERT_REPORT_FILE):
        print(f"[-] File '{CERT_REPORT_FILE}' not found.")
        print("    Run the certificate report script first.")
        return

    with open(CERT_REPORT_FILE, "r") as f:
        report_data = json.load(f)

    certificates = report_data.get("vcfCertificateModels", [])
    if not certificates:
        print("[-] No certificates found in the report.")
        return

    # --- Exclude root CA certificates (they do not support CSR generation) ---
    roots = [c for c in certificates if c.get("category") in SKIP_CATEGORIES]
    certificates = [c for c in certificates if c.get("category") not in SKIP_CATEGORIES]
    print(f"[*] {len(roots)} root certificate(s) excluded; {len(certificates)} candidate(s) for CSR.")
    if not certificates:
        print("[-] No certificates left to process.")
        return

    # --- Authentication ---
    token = get_auth_token(VCF_OPS_FQDN, VCF_OPS_USER, VCF_OPS_PASS)
    if not token:
        print("[-] Could not authenticate. Exiting.")
        return

    # --- Default values from the first certificate ---
    print("[*] Fetching default values from the first certificate...")
    first_cert_id = certificates[0].get("certificateResourceKey")
    if not first_cert_id:
        print("[-] The first certificate has no 'certificateResourceKey'.")
        return
    cert_details = get_certificate_details(VCF_OPS_FQDN, token, first_cert_id)
    if not cert_details:
        print("[-] Could not retrieve certificate details.")
        return

    defaults = extract_csr_defaults(cert_details)
    if not any(defaults.values()):
        defaults = {"country": "US", "organization": "MyCompany", "orgUnit": "IT",
                    "locality": "City", "state": "State", "email": "admin@mycompany.com"}

    CSR_SPEC = prompt_for_csr_spec(defaults)

    # --- Optional filter (useful for testing with a single component) ---
    flt = input("\nFilter by text in the FQDN (e.g. 'vidb'; empty = all): ").strip().lower()
    if flt:
        certificates = [c for c in certificates if flt in (c.get("applianceFqdn", "") or "").lower()]
        print(f"[*] {len(certificates)} certificate(s) match the filter.")

    # --- Duplicates: same appliance+FQDN as another entry, but without own SANs ---
    def key_of(c):
        return (c.get("appliance"), c.get("applianceFqdn"))

    def has_san(c):
        s = c.get("subjectAlternativeNames") or {}
        return bool(s.get("dns") or s.get("ip"))

    with_san = {key_of(c) for c in certificates if has_san(c)}
    dup_nosan = [c for c in certificates if not has_san(c) and key_of(c) in with_san]
    skip_ids = set()
    if dup_nosan:
        print(f"\n[!] {len(dup_nosan)} certificate(s) repeat the appliance+FQDN of another entry and have no SANs of their own.")
        print("    Generating an extra CSR for the same component may overwrite the previous private key.")
        if input("    Skip them? (Y/n): ").strip().lower() not in ("n", "no"):
            skip_ids = {c.get("certificateResourceKey") for c in dup_nosan}

    os.makedirs(CSR_OUTPUT_DIR, exist_ok=True)

    total = len(certificates)
    success, failures, skipped = 0, 0, 0
    failed_list = []

    print(f"\n[*] Processing {total} certificates...")
    print("=" * 80)

    for idx, cert in enumerate(certificates, start=1):
        cert_id = cert.get("certificateResourceKey")
        appliance = cert.get("appliance", "UNKNOWN")
        fqdn_component = cert.get("applianceFqdn", "unknown")
        label = f"{appliance} ({fqdn_component})"

        if cert_id in skip_ids:
            print(f"[{idx}/{total}] [~] Skipped (duplicate without SANs): {label}")
            skipped += 1
            continue

        payload = build_csr_payload(cert, CSR_SPEC)
        if not payload:
            print(f"[{idx}/{total}] [-] Skipped: missing certificateResourceKey or applianceFqdn ({label}).")
            failures += 1
            failed_list.append(label)
            continue

        spec = payload["generateCsrSpec"]
        san = spec["subjectAltNames"]
        print(f"[{idx}/{total}] Generating CSR for {label}...")
        print(f"    -> CN={spec['commonName']}  SAN DNS={san['dns']}  IP={san['ip']}")
        print(f"    -> certificateId={cert_id}")

        result = generate_csr(VCF_OPS_FQDN, token, payload)
        if not (result and result.get("requestId")):
            print(f"    [-] Failed to launch the workflow for {label}.")
            failures += 1
            failed_list.append(label)
            continue

        request_id = result["requestId"]
        print(f"    [+] Workflow launched. RequestId: {request_id}")

        max_retries = 30
        csr_content = None
        for attempt in range(max_retries):
            time.sleep(5)
            status = get_workflow_status(VCF_OPS_FQDN, token, request_id)
            state = (status or {}).get("state", "UNKNOWN")
            print(f"        Status: {state} (Attempt {attempt + 1}/{max_retries})")

            if state in ("COMPLETED", "SUCCESSFUL"):
                csr_content, items = get_generated_csr(VCF_OPS_FQDN, token, fqdn_component)
                if not csr_content:
                    dbg = f"debug_{appliance}_{request_id}.json"
                    print(f"    [-] CSR not found; response saved to {dbg}")
                    with open(dbg, "w") as fd:
                        json.dump(items, fd, indent=2)
                break

            if state in ("FAILED", "CANCELLED"):
                print("    [-] Workflow failed. Full details:")
                print(json.dumps(status, indent=2))
                break
        else:
            print(f"    [-] Timed out waiting for workflow {request_id}")

        if csr_content:
            safe_name = f"{appliance}_{fqdn_component}_{cert_id[:8]}".replace(".", "_").replace(":", "_")
            filepath = os.path.join(CSR_OUTPUT_DIR, f"{safe_name}.csr")
            with open(filepath, "w") as f_out:
                f_out.write(normalize_pem(csr_content))
            print(f"    [+] CSR saved to: {filepath}")
            success += 1
        else:
            print(f"    [-] Could not retrieve the CSR for {label}.")
            failures += 1
            failed_list.append(label)

    print("=" * 80)
    print(f"[*] Done. Successes: {success}, Failures: {failures}, Skipped: {skipped}")
    if failed_list:
        print("[*] Components with failures:")
        for item in failed_list:
            print(f"    - {item}")
    print(f"[*] CSRs are located in: {CSR_OUTPUT_DIR}/")


if __name__ == "__main__":
    main()