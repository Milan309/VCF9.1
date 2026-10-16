#!/usr/bin/env python3
"""
VCF 9.1 Certificate Management Tool - Interactive Menu

Consolidates three scripts into one interactive tool:
  1) Generate certificate report (recommended before anything else)
  2) Generate CSRs in bulk
  3) Import signed certificates in bulk

Each option prompts interactively for the parameters its original script
required via command-line flags.
"""

import getpass
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==========================================
# SHARED CONSTANTS
# ==========================================
TIMEOUT = 60
SKIP_CATEGORIES = {"ROOT_CERT"}
VALID_KEY_SIZES = ["KEY_2048", "KEY_3072", "KEY_4096"]
VALID_CA_TYPES = ["EXTERNAL_CA", "MSCA", "OPENSSL_CA", "SELF_SIGNED_CA", "VMCA"]
CERT_EXTENSIONS = (".crt", ".cer", ".pem")
MAX_POLL_ERRORS = 12
PAGE_SIZE = 500
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL)
CERT_REPORT_FILE = "certificates_report.json"
CSR_OUTPUT_DIR = "csrs_generated"
DEFAULT_CERTS_DIR = "signed_certs"


# ==========================================
# SHARED AUTH FUNCTIONS
# ==========================================
def get_auth_token(session, fqdn, user, password):
    """Get an authentication token from VCF Operations."""
    url = f"https://{fqdn}/suite-api/api/auth/token/acquire"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        r = session.post(url, headers=headers,
                         json={"username": user, "password": password}, timeout=TIMEOUT)
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
    """Release the token at the end (best effort)."""
    url = f"https://{fqdn}/suite-api/api/auth/token/release"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        session.post(url, headers=headers, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        pass


def ask_connection_settings(default_fqdn=None, default_user=None):
    """Prompt for FQDN, user and password. Returns (fqdn, user, password)."""
    print("\n[*] VCF Operations connection settings")
    fqdn = default_fqdn or input("  VCF Operations FQDN: ").strip()
    user = default_user or input("  Username (e.g. admin): ").strip()
    password = os.environ.get("VCF_OPS_PASSWORD") or getpass.getpass("  Password: ")
    return fqdn, user, password


def ask_yes_no(prompt, default=False):
    """Ask a yes/no question. Returns True if the user confirms."""
    suffix = " (Y/n): " if default else " (y/N): "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "s", "si", "sí")


# ============================================================================
# OPTION 1: GENERATE CERTIFICATE REPORT
# ============================================================================
def rpt_get_all_certificates(session, fqdn, token):
    """Query all certificates using pagination (de-duplicated)."""
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/certificates/query"
    headers = {
        "Authorization": f"OpsToken {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    certs_by_id, page, total = {}, 0, None

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


def rpt_sort_key(cert):
    days = cert.get("daysToExpire")
    return (days is None, days if days is not None else 0)


def rpt_print_summary_table(certificates):
    if not certificates:
        print("[!] No certificates found.")
        return
    width = 175
    print("\n" + "=" * width)
    print(f"{'Certificate ID (Resource Key)':<38} {'Component':<22} {'FQDN':<36} "
          f"{'Category':<14} {'Type':<12} {'Days left':>9}  {'Status':<12}")
    print("=" * width)
    for cert in sorted(certificates, key=rpt_sort_key):
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


def run_generate_report():
    """Interactive wrapper for Option 1: Generate certificate report."""
    print("\n" + "#" * 70)
    print("# OPTION 1 - Generate certificate report")
    print("#" * 70)

    fqdn, user, password = ask_connection_settings()
    output = input(f"  Output file [{CERT_REPORT_FILE}]: ").strip() or CERT_REPORT_FILE
    ca_bundle = input("  CA bundle path (empty = disable TLS verification): ").strip()

    session = requests.Session()
    if ca_bundle:
        session.verify = ca_bundle
    else:
        session.verify = False
        print("[!] TLS verification is disabled (lab use).")

    token = get_auth_token(session, fqdn, user, password)
    if not token:
        print("[-] Could not authenticate. Returning to menu.")
        return

    try:
        print("[*] Querying certificates from VCF Operations...")
        certificates = rpt_get_all_certificates(session, fqdn, token)

        if certificates is None:
            print("[-] Retrieval failed or was incomplete; report NOT saved.")
            return
        if not certificates:
            print("[-] No certificates retrieved. Check your permissions or environment.")
            return

        rpt_print_summary_table(certificates)

        output_data = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "source": fqdn,
            "vcfCertificateModels": certificates,
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        print(f"[+] Full report saved to '{output}'")
        print("[*] You can now run Option 2 to generate CSRs.")
    finally:
        release_token(session, fqdn, token)


# ============================================================================
# OPTION 2: GENERATE CSRs (BULK)
# ============================================================================
def csr_get_certificate_details(session, fqdn, token, certificate_id):
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/certificates/{certificate_id}"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        r = session.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error getting details for {certificate_id}: {e}")
        return None


def csr_parse_dn(dn_string):
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
    if "emailAddress" not in result and "1.2.840.113549.1.9.1" in result:
        result["emailAddress"] = result["1.2.840.113549.1.9.1"]
    return result


def csr_extract_defaults(cert_details):
    dn = csr_parse_dn(cert_details.get("issuedTo", ""))
    return {
        "country": dn.get("C", ""),
        "organization": dn.get("O", ""),
        "orgUnit": dn.get("OU", ""),
        "locality": dn.get("L", ""),
        "state": dn.get("ST", ""),
        "email": dn.get("emailAddress", ""),
    }


def csr_prompt_for_spec(defaults):
    print("\n" + "=" * 80)
    print("DEFAULT CSR VALUES (extracted from the first certificate)")
    print("=" * 80)
    for key, value in defaults.items():
        print(f"  {key:<15}: {value}")
    print("=" * 80)

    key_size = "KEY_2048"
    key_algorithm = "RSA"

    if ask_yes_no("\nDo you want to replace these values for all components?", default=False):
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
        print(f"[!] keySize '{key_size}' is not valid; using KEY_2048.")
        key_size = "KEY_2048"

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
    csr_spec = {k: v for k, v in csr_spec.items() if v}
    print("\n[*] Final CSR specification:")
    for k, v in csr_spec.items():
        print(f"    {k}: {v}")
    return csr_spec


def csr_build_payload(cert, csr_spec):
    cn = cert.get("applianceFqdn")
    cert_id = cert.get("certificateResourceKey")
    if not cn or not cert_id:
        return None
    san = cert.get("subjectAlternativeNames") or {}
    dns = list(san.get("dns") or [])
    ip = list(san.get("ip") or [])
    if cn not in dns:
        dns.insert(0, cn)
    spec = {**csr_spec, "commonName": cn,
            "subjectAltNames": {"dns": dns, "ip": ip}}
    return {"certificateId": cert_id, "generateCsrSpec": spec}


def csr_generate(session, fqdn, token, payload):
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/csrs"
    headers = {"Authorization": f"OpsToken {token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    try:
        r = session.post(url, headers=headers, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error generating CSR: {e}")
        if getattr(e, "response", None) is not None:
            print(f"    Detail: {e.response.text}")
        return None


def csr_get_workflow_status(session, fqdn, token, request_id):
    url = f"https://{fqdn}/suite-api/api/workflows/requests/{request_id}"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        r = session.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error checking request {request_id}: {e}")
        return None


def csr_get_generated(session, fqdn, token, common_name):
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/csrs"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    items, page = [], 0
    while True:
        params = {"page": page, "pageSize": 100}
        try:
            r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
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


def csr_normalize_pem(csr):
    body = re.sub(r"-----(BEGIN|END) CERTIFICATE REQUEST-----", "", csr)
    body = "".join(body.split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE REQUEST-----\n"
            + "\n".join(lines)
            + "\n-----END CERTIFICATE REQUEST-----\n")


def run_generate_csr():
    """Interactive wrapper for Option 2: Generate CSRs in bulk."""
    print("\n" + "#" * 70)
    print("# OPTION 2 - Generate CSRs in bulk")
    print("#" * 70)

    if not os.path.exists(CERT_REPORT_FILE):
        print(f"[-] File '{CERT_REPORT_FILE}' not found.")
        print("    Please run Option 1 first to generate the certificate report.")
        return

    fqdn, user, password = ask_connection_settings()

    with open(CERT_REPORT_FILE, "r") as f:
        report_data = json.load(f)

    certificates = report_data.get("vcfCertificateModels", [])
    if not certificates:
        print("[-] No certificates found in the report.")
        return

    roots = [c for c in certificates if c.get("category") in SKIP_CATEGORIES]
    certificates = [c for c in certificates if c.get("category") not in SKIP_CATEGORIES]
    print(f"[*] {len(roots)} root certificate(s) excluded; {len(certificates)} candidate(s) for CSR.")
    if not certificates:
        print("[-] No certificates left to process.")
        return

    session = requests.Session()
    session.verify = False
    print("[!] TLS verification is disabled (lab use).")

    token = get_auth_token(session, fqdn, user, password)
    if not token:
        print("[-] Could not authenticate. Returning to menu.")
        return

    # --- Default values from first certificate ---
    print("[*] Fetching default values from the first certificate...")
    first_cert_id = certificates[0].get("certificateResourceKey")
    if not first_cert_id:
        print("[-] The first certificate has no 'certificateResourceKey'.")
        release_token(session, fqdn, token)
        return
    cert_details = csr_get_certificate_details(session, fqdn, token, first_cert_id)
    if not cert_details:
        print("[-] Could not retrieve certificate details.")
        release_token(session, fqdn, token)
        return

    defaults = csr_extract_defaults(cert_details)
    if not any(defaults.values()):
        defaults = {"country": "US", "organization": "MyCompany", "orgUnit": "IT",
                    "locality": "City", "state": "State", "email": "admin@mycompany.com"}

    CSR_SPEC = csr_prompt_for_spec(defaults)

    # --- Optional filter ---
    flt = input("\nFilter by text in the FQDN (e.g. 'vidb'; empty = all): ").strip().lower()
    if flt:
        certificates = [c for c in certificates if flt in (c.get("applianceFqdn", "") or "").lower()]
        print(f"[*] {len(certificates)} certificate(s) match the filter.")

    # --- Duplicate detection ---
    def key_of(c):
        return (c.get("appliance"), c.get("applianceFqdn"))

    def has_san(c):
        s = c.get("subjectAlternativeNames") or {}
        return bool(s.get("dns") or s.get("ip"))

    with_san = {key_of(c) for c in certificates if has_san(c)}
    dup_nosan = [c for c in certificates if not has_san(c) and key_of(c) in with_san]
    skip_ids = set()
    if dup_nosan:
        print(f"\n[!] {len(dup_nosan)} certificate(s) repeat the appliance+FQDN of another entry "
              f"and have no SANs of their own.")
        print("    Generating an extra CSR for the same component may overwrite the previous private key.")
        if ask_yes_no("    Skip them?", default=True):
            skip_ids = {c.get("certificateResourceKey") for c in dup_nosan}

    os.makedirs(CSR_OUTPUT_DIR, exist_ok=True)

    total = len(certificates)
    success, failures, skipped = 0, 0, 0
    failed_list = []

    print(f"\n[*] Processing {total} certificates...")
    print("=" * 80)

    try:
        for idx, cert in enumerate(certificates, start=1):
            cert_id = cert.get("certificateResourceKey")
            appliance = cert.get("appliance", "UNKNOWN")
            fqdn_component = cert.get("applianceFqdn", "unknown")
            label = f"{appliance} ({fqdn_component})"

            if cert_id in skip_ids:
                print(f"[{idx}/{total}] [~] Skipped (duplicate without SANs): {label}")
                skipped += 1
                continue

            payload = csr_build_payload(cert, CSR_SPEC)
            if not payload:
                print(f"[{idx}/{total}] [-] Skipped: missing data ({label}).")
                failures += 1
                failed_list.append(label)
                continue

            spec = payload["generateCsrSpec"]
            san = spec["subjectAltNames"]
            print(f"[{idx}/{total}] Generating CSR for {label}...")
            print(f"    -> CN={spec['commonName']}  SAN DNS={san['dns']}  IP={san['ip']}")
            print(f"    -> certificateId={cert_id}")

            result = csr_generate(session, fqdn, token, payload)
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
                status = csr_get_workflow_status(session, fqdn, token, request_id)
                state = (status or {}).get("state", "UNKNOWN")
                print(f"        Status: {state} (Attempt {attempt + 1}/{max_retries})")

                if state in ("COMPLETED", "SUCCESSFUL"):
                    csr_content, items = csr_get_generated(session, fqdn, token, fqdn_component)
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
                    f_out.write(csr_normalize_pem(csr_content))
                print(f"    [+] CSR saved to: {filepath}")
                success += 1
            else:
                print(f"    [-] Could not retrieve the CSR for {label}.")
                failures += 1
                failed_list.append(label)
    finally:
        release_token(session, fqdn, token)

    print("=" * 80)
    print(f"[*] Done. Successes: {success}, Failures: {failures}, Skipped: {skipped}")
    if failed_list:
        print("[*] Components with failures:")
        for item in failed_list:
            print(f"    - {item}")
    print(f"[*] CSRs are located in: {CSR_OUTPUT_DIR}/")


# ============================================================================
# OPTION 3: IMPORT SIGNED CERTIFICATES (BULK)
# ============================================================================
def imp_normalize_block(body):
    body = "".join(body.split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines)
            + "\n-----END CERTIFICATE-----")


def imp_read_pem_blocks(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return [imp_normalize_block(b) for b in PEM_RE.findall(text)]


def imp_block_key(block):
    return "".join(block.split())


def imp_build_chain(leaf, extra_blocks, chain_blocks):
    seen, out = set(), []
    for b in [leaf] + list(extra_blocks) + list(chain_blocks):
        k = imp_block_key(b)
        if k not in seen:
            seen.add(k)
            out.append(b)
    return "\n".join(out) + "\n"


def imp_have_openssl():
    return shutil.which("openssl") is not None


def imp_run_openssl(args, input_text=None):
    return subprocess.run(["openssl"] + args, input=input_text,
                          capture_output=True, text=True)


def imp_cert_info(pem):
    r = imp_run_openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253",
                         "-ext", "subjectAltName"], pem)
    if r.returncode != 0:
        r = imp_run_openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem)
        if r.returncode != 0:
            return None
    out = r.stdout
    m = re.search(r"CN=([^,\n]+)", out)
    return {
        "cn": m.group(1).strip() if m else "",
        "dns": re.findall(r"DNS:([^\s,]+)", out),
        "ip": re.findall(r"IP Address:([^\s,]+)", out),
    }


def imp_cert_serial(pem):
    if not imp_have_openssl():
        return ""
    r = imp_run_openssl(["x509", "-noout", "-serial"], pem)
    if r.returncode != 0:
        return ""
    return r.stdout.strip().replace("serial=", "")


def imp_is_expired(pem):
    return imp_run_openssl(["x509", "-noout", "-checkend", "0"], pem).returncode != 0


def imp_pubkey_of_cert(pem):
    r = imp_run_openssl(["x509", "-noout", "-pubkey"], pem)
    return "".join(r.stdout.split()) if r.returncode == 0 else None


def imp_pubkey_of_csr(path):
    r = imp_run_openssl(["req", "-noout", "-pubkey", "-in", path])
    return "".join(r.stdout.split()) if r.returncode == 0 else None


def imp_verify_chain(leaf, ca_blocks):
    with tempfile.TemporaryDirectory() as tmp:
        leaf_path = os.path.join(tmp, "leaf.pem")
        ca_path = os.path.join(tmp, "ca.pem")
        with open(leaf_path, "w") as f:
            f.write(leaf + "\n")
        with open(ca_path, "w") as f:
            f.write("\n".join(ca_blocks) + "\n")
        r = imp_run_openssl(["verify", "-CAfile", ca_path, leaf_path])
        if r.returncode == 0:
            return True, "OK"
        msg = (r.stdout + r.stderr).strip().splitlines()
        return False, msg[-1] if msg else "verification failed"


def imp_fingerprint_of_pem(pem):
    try:
        der = ssl.PEM_cert_to_DER_cert(pem + "\n")
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest().upper()


def imp_served_cert_fingerprint(host, port, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    return hashlib.sha256(der).hexdigest().upper() if der else None


def imp_verify_served(host, port, expected_fp, attempts=6, delay=10):
    served = None
    for i in range(attempts):
        served = imp_served_cert_fingerprint(host, port)
        if served == expected_fp:
            return "VERIFIED"
        if i < attempts - 1:
            time.sleep(delay)
    return "MISMATCH" if served else "UNREACHABLE"


def imp_safe_name(appliance, fqdn, cert_id):
    return f"{appliance}_{fqdn}_{cert_id[:8]}".replace(".", "_").replace(":", "_")


def imp_name_selected(fqdn, only, exclude):
    f = (fqdn or "").lower()
    if only and not any(o.lower() in f for o in only):
        return False
    if exclude and any(x.lower() in f for x in exclude):
        return False
    return True


def imp_match_entry(stem, info, candidates):
    for c in candidates:
        name = imp_safe_name(c.get("appliance", "UNKNOWN"), c.get("applianceFqdn", ""),
                             c.get("certificateResourceKey", ""))
        if name == stem:
            return c, None
    if not info:
        return None, "no file-name match and certificate could not be parsed"
    names = {n.lower() for n in info["dns"]}
    if info["cn"]:
        names.add(info["cn"].lower())
    matches = [c for c in candidates if (c.get("applianceFqdn") or "").lower() in names]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        ids = ", ".join(m.get("certificateResourceKey", "?")[:8] for m in matches)
        return None, f"ambiguous: several managed certificates share this FQDN ({ids})"
    return None, "no managed certificate matches this CN/SAN"


def imp_precheck(leaf, ca_blocks, info, entry, csr_path):
    problems, warnings = [], []
    if not imp_have_openssl():
        return problems, ["openssl not found; pre-checks skipped"]
    if imp_is_expired(leaf):
        problems.append("signed certificate is expired")
    fqdn = (entry.get("applianceFqdn") or "").lower()
    if info:
        san_names = [n.lower() for n in info["dns"]]
        if not san_names:
            problems.append("signed certificate has no SAN DNS entries")
        elif fqdn not in san_names:
            problems.append(f"{fqdn} not present in the SAN DNS entries")
        if len(san_names) != len(set(san_names)):
            problems.append("duplicate SAN DNS entries")
        expected_ips = (entry.get("subjectAlternativeNames") or {}).get("ip") or []
        missing = [ip for ip in expected_ips if ip not in info["ip"]]
        if missing:
            warnings.append(f"IP SAN(s) missing: {missing}")
    else:
        warnings.append("could not parse CN/SAN")
    if csr_path and os.path.exists(csr_path):
        csr_key, crt_key = imp_pubkey_of_csr(csr_path), imp_pubkey_of_cert(leaf)
        if csr_key and crt_key:
            if csr_key != crt_key:
                problems.append("public key does not match the generated CSR")
        else:
            warnings.append("could not compare public keys")
    else:
        warnings.append("CSR file not found; key match not verified")
    if ca_blocks:
        ok, msg = imp_verify_chain(leaf, ca_blocks)
        if not ok:
            problems.append(f"chain verification failed: {msg}")
    else:
        warnings.append("no CA chain supplied; chain not verified")
    return problems, warnings


def imp_replace_certificate(session, fqdn, token, cert_id, ca_type, chain_text):
    url = f"https://{fqdn}/suite-api/api/fleet-management/certificate-management/certificates/{cert_id}"
    headers = {"Authorization": f"OpsToken {token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    payload = {"caType": ca_type, "certificateChain": chain_text}
    try:
        r = session.put(url, headers=headers, json=payload, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        print(f"    [-] Request error: {e}")
        return None
    if r.status_code not in (200, 202):
        print(f"    [-] HTTP {r.status_code}: {r.text}")
        return None
    return r.json()


def imp_wait_for_workflow(session, fqdn, token, request_id, timeout, interval):
    url = f"https://{fqdn}/suite-api/api/workflows/requests/{request_id}"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    start, errors, attempt = time.time(), 0, 0
    while time.time() - start < timeout:
        time.sleep(interval)
        attempt += 1
        try:
            r = session.get(url, headers=headers, timeout=TIMEOUT)
            r.raise_for_status()
            status = r.json()
            errors = 0
        except requests.exceptions.RequestException as e:
            errors += 1
            print(f"        (status check failed: {e}; {errors}/{MAX_POLL_ERRORS})")
            if errors >= MAX_POLL_ERRORS:
                return "UNKNOWN", None
            continue
        state = status.get("state", "UNKNOWN")
        print(f"        Status: {state} (check {attempt}, {int(time.time() - start)}s)")
        if state in ("COMPLETED", "SUCCESSFUL", "FAILED", "CANCELLED"):
            return state, status
    return "TIMEOUT", None


def run_import_certificates():
    """Interactive wrapper for Option 3: Import signed certificates in bulk."""
    print("\n" + "#" * 70)
    print("# OPTION 3 - Import signed certificates in bulk")
    print("#" * 70)

    if not os.path.exists(CERT_REPORT_FILE):
        print(f"[-] File '{CERT_REPORT_FILE}' not found.")
        print("    Please run Option 1 first to generate the certificate report.")
        return
    if not os.path.isdir(DEFAULT_CERTS_DIR):
        print(f"[-] Folder '{DEFAULT_CERTS_DIR}' not found.")
        print(f"    Please put the signed certificates there.")
        return

    print("\n[*] Import settings")
    certs_dir = input(f"  Signed certificates folder [{DEFAULT_CERTS_DIR}]: ").strip() or DEFAULT_CERTS_DIR
    csr_dir = input(f"  CSRs folder [{CSR_OUTPUT_DIR}]: ").strip() or CSR_OUTPUT_DIR
    chain_input = input("  CA chain PEM file (intermediate+root, empty to skip): ").strip()
    chain_files = [chain_input] if chain_input else []
    port = int(input("  TLS port to verify served certificates [443]: ").strip() or "443")
    ca_type = input(f"  caType {VALID_CA_TYPES} [EXTERNAL_CA]: ").strip() or "EXTERNAL_CA"
    if ca_type not in VALID_CA_TYPES:
        print(f"[!] Invalid caType, using EXTERNAL_CA.")
        ca_type = "EXTERNAL_CA"

    only_input = input("  Only process FQDNs containing (comma-separated, empty=all): ").strip()
    only = [s.strip() for s in only_input.split(",") if s.strip()] or None
    exclude_input = input("  Exclude FQDNs containing (comma-separated, empty=none): ").strip()
    exclude = [s.strip() for s in exclude_input.split(",") if s.strip()] or None

    dry_run = ask_yes_no("  Dry-run (no changes)?", default=True)
    if dry_run:
        force = False
        stop_on_failure = False
        auto_yes = False
    else:
        force = ask_yes_no("  Force replace even if already installed?", default=False)
        stop_on_failure = ask_yes_no("  Stop on first failure?", default=False)
        auto_yes = ask_yes_no("  Skip the final confirmation?", default=False)

    # --- Load report ---
    with open(CERT_REPORT_FILE, "r", encoding="utf-8") as f:
        report = json.load(f)
    candidates = [c for c in report.get("vcfCertificateModels", [])
                  if c.get("category") not in SKIP_CATEGORIES
                  and c.get("certificateResourceKey") and c.get("applianceFqdn")]
    if not candidates:
        print("[-] No replaceable certificates found in the report.")
        return

    # --- Load CA chain ---
    chain_blocks = []
    for path in chain_files:
        if not os.path.exists(path):
            print(f"[-] Chain file '{path}' not found.")
            return
        blocks = imp_read_pem_blocks(path)
        if not blocks:
            print(f"[-] No PEM certificates found in chain file '{path}'.")
            return
        chain_blocks.extend(blocks)
    print(f"[*] CA chain: {len(chain_blocks)} certificate(s) loaded.")

    if not chain_blocks and not dry_run:
        print("[-] No CA chain supplied. Refusing to proceed without it.")
        return

    openssl_ok = imp_have_openssl()
    if not openssl_ok:
        print("[!] openssl not found; pre-checks will be skipped.")

    if not os.path.isdir(certs_dir):
        print(f"[-] Folder '{certs_dir}' not found.")
        return

    files = sorted(os.path.join(certs_dir, n) for n in os.listdir(certs_dir)
                   if n.lower().endswith(CERT_EXTENSIONS))
    if not files:
        print(f"[-] No {CERT_EXTENSIONS} files in '{certs_dir}'.")
        return

    # --- Build plan ---
    plan, skipped = {}, []
    for path in files:
        name = os.path.basename(path)
        stem = os.path.splitext(name)[0]
        blocks = imp_read_pem_blocks(path)
        if not blocks:
            skipped.append((name, "no PEM certificate found"))
            continue
        leaf, extra = blocks[0], blocks[1:]
        info = imp_cert_info(leaf) if openssl_ok else None

        entry, why = imp_match_entry(stem, info, candidates)
        if not entry:
            skipped.append((name, why))
            continue
        if not imp_name_selected(entry["applianceFqdn"], only, exclude):
            continue

        cert_id = entry["certificateResourceKey"]
        if cert_id in plan:
            skipped.append((name, f"duplicate of {plan[cert_id]['file']}"))
            continue

        problems, warnings = [], []
        if openssl_ok:
            csr_path = os.path.join(csr_dir, imp_safe_name(
                entry.get("appliance", "UNKNOWN"), entry["applianceFqdn"], cert_id) + ".csr")
            problems, warnings = imp_precheck(leaf, extra + chain_blocks, info, entry, csr_path)

        plan[cert_id] = {
            "file": name, "entry": entry, "problems": problems, "warnings": warnings,
            "chain": imp_build_chain(leaf, extra, chain_blocks),
            "fp": imp_fingerprint_of_pem(leaf), "serial": imp_cert_serial(leaf),
            "installed": False,
        }

    # --- Installed-check ---
    if not force:
        print("[*] Checking which components already serve the signed certificate...")
        for p in plan.values():
            if p["problems"] or not p["fp"]:
                continue
            served = imp_served_cert_fingerprint(p["entry"]["applianceFqdn"], port)
            if served is None:
                p["warnings"].append(f"could not read cert on port {port}; installed-check skipped")
            elif served == p["fp"]:
                p["installed"] = True

    # --- Show plan ---
    items = sorted(plan.values(),
                   key=lambda p: (p["entry"].get("appliance") == "VCF_OPERATIONS",
                                  p["entry"]["applianceFqdn"]))
    print("\n" + "=" * 110)
    print(f"{'Component':<24} {'FQDN':<36} {'File':<32} Result")
    print("=" * 110)
    for p in items:
        e = p["entry"]
        if p["problems"]:
            result = "BLOCKED"
        elif p["installed"]:
            result = "ALREADY INSTALLED"
        elif p["warnings"]:
            result = "OK (warnings)"
        else:
            result = "OK"
        print(f"{e.get('appliance', 'N/A'):<24} {e['applianceFqdn']:<36} {p['file']:<32} {result}")
        for m in p["problems"]:
            print(f"      [x] {m}")
        for m in p["warnings"]:
            print(f"      [!] {m}")
    for name, why in skipped:
        print(f"{'(skipped)':<24} {name:<36} {why}")
    print("=" * 110)

    ready = [p for p in items if not p["problems"] and not p["installed"]]
    installed = [p for p in items if p["installed"] and not p["problems"]]
    blocked = [p for p in items if p["problems"]]
    print(f"[*] {len(ready)} ready, {len(installed)} already installed, "
          f"{len(blocked)} blocked, {len(skipped)} skipped.")

    if dry_run:
        print("[*] Dry run: nothing was changed.")
        return
    if not ready:
        if installed and not blocked:
            print("[*] Nothing to do: all matching certificates are already installed.")
        else:
            print("[-] Nothing to import.")
        return

    if not auto_yes:
        print("\n[!] Replacing a certificate restarts services on that component.")
        print("    VCF_OPERATIONS (if included) is processed last.")
        if input("    Type 'yes' to continue: ").strip().lower() != "yes":
            print("[*] Cancelled.")
            return

    # --- Connect ---
    fqdn, user, password = ask_connection_settings()

    session = requests.Session()
    session.verify = False
    print("[!] TLS verification is disabled (lab use).")

    token = get_auth_token(session, fqdn, user, password)
    if not token:
        print("[-] Could not authenticate. Returning to menu.")
        return

    success, failures = 0, 0
    failed_list, unverified_list, not_processed = [], [], []
    total = len(ready)

    try:
        print(f"\n[*] Replacing {total} certificate(s)...")
        print("=" * 110)
        for idx, p in enumerate(ready, start=1):
            if stop_on_failure and failures:
                not_processed.append(f"{p['entry'].get('appliance', 'UNKNOWN')} ({p['entry']['applianceFqdn']})")
                continue

            e = p["entry"]
            cert_id = e["certificateResourceKey"]
            host = e["applianceFqdn"]
            label = f"{e.get('appliance', 'UNKNOWN')} ({host})"
            print(f"[{idx}/{total}] Replacing certificate for {label}")
            print(f"    -> file={p['file']}  certificateId={cert_id}  caType={ca_type}")

            result = imp_replace_certificate(session, fqdn, token, cert_id, ca_type, p["chain"])
            if not (result and result.get("requestId")):
                print(f"    [-] Could not launch the workflow for {label}.")
                failures += 1
                failed_list.append(label)
                continue

            request_id = result["requestId"]
            print(f"    [+] Workflow launched. RequestId: {request_id}")

            state, status = imp_wait_for_workflow(session, fqdn, token, request_id, 1800, 10)
            if state in ("COMPLETED", "SUCCESSFUL"):
                print(f"    [+] Workflow completed for {label}.")
                if p["fp"]:
                    outcome = imp_verify_served(host, port, p["fp"])
                    if outcome == "VERIFIED":
                        print(f"    [+] Verified: {host}:{port} now serves the signed certificate.")
                        success += 1
                    elif outcome == "MISMATCH":
                        print(f"    [-] Workflow completed but {host}:{port} still serves a different cert.")
                        failures += 1
                        failed_list.append(f"{label} [VERIFY MISMATCH]")
                    else:
                        print(f"    [!] Could not connect to {host}:{port} to verify.")
                        success += 1
                        unverified_list.append(label)
                else:
                    success += 1
            else:
                print(f"    [-] Workflow ended with state {state}.")
                if status:
                    print(json.dumps(status, indent=2))
                failures += 1
                failed_list.append(f"{label} [{state}]")
    finally:
        release_token(session, fqdn, token)

    print("=" * 110)
    print(f"[*] Done. Successes: {success}, Failures: {failures}, "
          f"Already installed: {len(installed)}, Blocked: {len(blocked)}, Skipped: {len(skipped)}")
    if failed_list:
        print("[*] Components with failures:")
        for item in failed_list:
            print(f"    - {item}")
    if unverified_list:
        print("[*] Completed but not verified (check them manually):")
        for item in unverified_list:
            print(f"    - {item}")
    if not_processed:
        print("[*] Not processed because of --stop-on-failure:")
        for item in not_processed:
            print(f"    - {item}")


# ============================================================================
# MENU
# ============================================================================
def print_menu():
    print("\n" + "=" * 70)
    print("  VCF 9.1 Certificate Management Tool")
    print("=" * 70)
    print("  1) Generate certificate report    [RECOMMENDED FIRST]")
    print("  2) Generate CSRs (bulk)")
    print("  3) Import signed certificates (bulk)")
    print("  0) Exit")
    print("=" * 70)


def main():
    while True:
        print_menu()
        choice = input("  Select an option: ").strip()
        if choice == "1":
            try:
                run_generate_report()
            except KeyboardInterrupt:
                print("\n[!] Interrupted by user.")
        elif choice == "2":
            try:
                run_generate_csr()
            except KeyboardInterrupt:
                print("\n[!] Interrupted by user.")
        elif choice == "3":
            try:
                run_import_certificates()
            except KeyboardInterrupt:
                print("\n[!] Interrupted by user.")
        elif choice in ("0", "q", "quit", "exit"):
            print("[*] Goodbye.")
            sys.exit(0)
        else:
            print("[!] Invalid option, try again.")


if __name__ == "__main__":
    main()