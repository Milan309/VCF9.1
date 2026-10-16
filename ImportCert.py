#!/usr/bin/env python3
"""
Bulk signed-certificate importer for VCF Operations 9.1 (Fleet Management > Certificates).

What it does:
  - Reads certificates_report.json (output of the certificate report script).
  - Reads signed certificates (.crt / .cer / .pem, PEM-encoded) from a folder.
  - Matches each signed certificate to a managed certificate:
      1) by file name (same base name used by the bulk CSR script), or
      2) by CN / SAN DNS of the signed certificate vs. the component FQDN.
  - Pre-checks each certificate with openssl (expiry, SAN, public key vs. the
    CSR that was generated, chain verification) before touching anything.
  - Skips components that already serve the signed certificate (SHA-256
    fingerprint comparison against what the component presents on its TLS port).
  - Builds the chain (leaf first, then intermediate(s) and root) and calls
    "Replace Certificate" for each component, waiting for each workflow to finish.
  - After each successful workflow, verifies that the component really serves
    the new certificate.
  - VCF_OPERATIONS is always processed last (its services restart).

Folder layout (defaults):
  ./certificates_report.json
  ./csrs_generated/*.csr         (from the bulk CSR script, used for key matching)
  ./signed_certs/*.pem           (signed certificates returned by your CA)
  ./ca_chain.pem                 (intermediate(s) + root CA, PEM, passed with --chain)

Usage examples:
  Dry run (no changes, no login needed):
      python3 ImportCert.py --chain ca_chain.pem --dry-run
  One or several components (substring match on the FQDN):
      python3 ImportCert.py --chain ca_chain.pem --only esx-03a esx-04a
  Everything except some components, stopping at the first failure:
      python3 ImportCert.py --chain ca_chain.pem --exclude auto- ops-a --stop-on-failure

Notes:
  - Replacing a certificate restarts services on that component. Use a maintenance window.
  - Do NOT regenerate a CSR after submitting it to the CA: the API rejects (HTTP 400)
    a leaf certificate that does not match a CSR stored in VCF Operations.
  - SSL verification to the VCF Operations API is disabled by default (lab use).
    Use --ca-bundle in production.
  - Password can be provided with the VCF_OPS_PASSWORD environment variable.
"""

import argparse
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

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 60
SKIP_CATEGORIES = {"ROOT_CERT"}            # root CAs are not replaceable via this flow
VALID_CA_TYPES = ["EXTERNAL_CA", "MSCA", "OPENSSL_CA", "SELF_SIGNED_CA", "VMCA"]
CERT_EXTENSIONS = (".crt", ".cer", ".pem")
MAX_POLL_ERRORS = 12                       # tolerated consecutive status-check failures
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL)


# ==========================================
# PEM / OPENSSL HELPERS
# ==========================================

def normalize_block(body):
    """Return a clean single-certificate PEM block (64 chars per line)."""
    body = "".join(body.split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines)
            + "\n-----END CERTIFICATE-----")


def read_pem_blocks(path):
    """Return every PEM certificate block found in a file, in order."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return [normalize_block(b) for b in PEM_RE.findall(text)]


def block_key(block):
    return "".join(block.split())


def build_chain(leaf, extra_blocks, chain_blocks):
    """Leaf first, then any extra certs from the same file, then the CA chain (de-duplicated)."""
    seen, out = set(), []
    for b in [leaf] + list(extra_blocks) + list(chain_blocks):
        k = block_key(b)
        if k not in seen:
            seen.add(k)
            out.append(b)
    return "\n".join(out) + "\n"


def have_openssl():
    return shutil.which("openssl") is not None


def run_openssl(args, input_text=None):
    return subprocess.run(["openssl"] + args, input=input_text,
                          capture_output=True, text=True)


def cert_info(pem):
    """Extract CN, SAN DNS and SAN IPs from a PEM certificate using openssl."""
    r = run_openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253",
                     "-ext", "subjectAltName"], pem)
    if r.returncode != 0:   # fallback: older openssl without -ext, or no SAN extension
        r = run_openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem)
        if r.returncode != 0:
            return None
    out = r.stdout
    m = re.search(r"CN=([^,\n]+)", out)
    return {
        "cn": m.group(1).strip() if m else "",
        "dns": re.findall(r"DNS:([^\s,]+)", out),
        "ip": re.findall(r"IP Address:([^\s,]+)", out),
    }


def cert_serial(pem):
    """Return the certificate serial (hex) using openssl, or '' if unavailable."""
    if not have_openssl():
        return ""
    r = run_openssl(["x509", "-noout", "-serial"], pem)
    if r.returncode != 0:
        return ""
    return r.stdout.strip().replace("serial=", "")


def is_expired(pem):
    return run_openssl(["x509", "-noout", "-checkend", "0"], pem).returncode != 0


def pubkey_of_cert(pem):
    r = run_openssl(["x509", "-noout", "-pubkey"], pem)
    return "".join(r.stdout.split()) if r.returncode == 0 else None


def pubkey_of_csr(path):
    r = run_openssl(["req", "-noout", "-pubkey", "-in", path])
    return "".join(r.stdout.split()) if r.returncode == 0 else None


def verify_chain(leaf, ca_blocks):
    """Verify leaf against the supplied CA certificates. Returns (ok, message)."""
    with tempfile.TemporaryDirectory() as tmp:
        leaf_path = os.path.join(tmp, "leaf.pem")
        ca_path = os.path.join(tmp, "ca.pem")
        with open(leaf_path, "w") as f:
            f.write(leaf + "\n")
        with open(ca_path, "w") as f:
            f.write("\n".join(ca_blocks) + "\n")
        r = run_openssl(["verify", "-CAfile", ca_path, leaf_path])
        if r.returncode == 0:
            return True, "OK"
        msg = (r.stdout + r.stderr).strip().splitlines()
        return False, msg[-1] if msg else "verification failed"


# ==========================================
# TLS FINGERPRINT HELPERS (installed-check / post-verification)
# ==========================================

def fingerprint_of_pem(pem):
    """SHA-256 fingerprint (uppercase hex) of a PEM certificate block, or None."""
    try:
        der = ssl.PEM_cert_to_DER_cert(pem + "\n")
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest().upper()


def served_cert_fingerprint(host, port, timeout=8):
    """SHA-256 fingerprint of the certificate currently presented by host:port, or None."""
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


def verify_served(host, port, expected_fp, attempts=6, delay=10):
    """Wait for the component to present the expected certificate.
    Returns 'VERIFIED', 'MISMATCH' or 'UNREACHABLE'."""
    served = None
    for i in range(attempts):
        served = served_cert_fingerprint(host, port)
        if served == expected_fp:
            return "VERIFIED"
        if i < attempts - 1:
            time.sleep(delay)
    return "MISMATCH" if served else "UNREACHABLE"


# ==========================================
# MATCHING / PRE-CHECKS
# ==========================================

def safe_name(appliance, fqdn, cert_id):
    """Same naming used by the bulk CSR script for its .csr files."""
    return f"{appliance}_{fqdn}_{cert_id[:8]}".replace(".", "_").replace(":", "_")


def name_selected(fqdn, only, exclude):
    f = (fqdn or "").lower()
    if only and not any(o.lower() in f for o in only):
        return False
    if exclude and any(x.lower() in f for x in exclude):
        return False
    return True


def match_entry(stem, info, candidates):
    """Return (report_entry, reason_if_none)."""
    for c in candidates:
        name = safe_name(c.get("appliance", "UNKNOWN"), c.get("applianceFqdn", ""),
                         c.get("certificateResourceKey", ""))
        if name == stem:
            return c, None

    if not info:
        return None, "no file-name match and certificate could not be parsed with openssl"

    names = {n.lower() for n in info["dns"]}
    if info["cn"]:
        names.add(info["cn"].lower())
    matches = [c for c in candidates if (c.get("applianceFqdn") or "").lower() in names]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        ids = ", ".join(m.get("certificateResourceKey", "?")[:8] for m in matches)
        return None, f"ambiguous: several managed certificates share this FQDN ({ids}); rename the file like its CSR"
    return None, "no managed certificate matches this CN/SAN"


def precheck(leaf, ca_blocks, info, entry, csr_path):
    """Return (problems, warnings)."""
    problems, warnings = [], []
    if not have_openssl():
        return problems, ["openssl not found; pre-checks skipped"]

    if is_expired(leaf):
        problems.append("signed certificate is expired")

    fqdn = (entry.get("applianceFqdn") or "").lower()
    if info:
        san_names = [n.lower() for n in info["dns"]]
        if not san_names:
            problems.append("signed certificate has no SAN DNS entries (required by modern TLS clients)")
        elif fqdn not in san_names:
            problems.append(f"{fqdn} not present in the SAN DNS entries of the signed certificate")
        if len(san_names) != len(set(san_names)):
            problems.append("duplicate SAN DNS entries (can break the VCF Automation gateway)")
        expected_ips = (entry.get("subjectAlternativeNames") or {}).get("ip") or []
        missing = [ip for ip in expected_ips if ip not in info["ip"]]
        if missing:
            warnings.append(f"IP SAN(s) missing in signed certificate: {missing}")
    else:
        warnings.append("could not parse CN/SAN")

    if csr_path and os.path.exists(csr_path):
        csr_key, crt_key = pubkey_of_csr(csr_path), pubkey_of_cert(leaf)
        if csr_key and crt_key:
            if csr_key != crt_key:
                problems.append("public key does not match the generated CSR "
                                "(was the CSR regenerated after signing?)")
        else:
            warnings.append("could not compare public keys")
    else:
        warnings.append("CSR file not found; key match not verified")

    if ca_blocks:
        ok, msg = verify_chain(leaf, ca_blocks)
        if not ok:
            problems.append(f"chain verification failed: {msg}")
    else:
        warnings.append("no CA chain supplied (--chain); chain not verified")

    return problems, warnings


# ==========================================
# API FUNCTIONS
# ==========================================

def get_auth_token(session, fqdn, user, password):
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
    url = f"https://{fqdn}/suite-api/api/auth/token/release"
    headers = {"Authorization": f"OpsToken {token}", "Accept": "application/json"}
    try:
        session.post(url, headers=headers, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        pass


def replace_certificate(session, fqdn, token, cert_id, ca_type, chain_text):
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


def wait_for_workflow(session, fqdn, token, request_id, timeout, interval):
    """Poll a workflow request. Returns (state, status_json_or_None)."""
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


# ==========================================
# MAIN
# ==========================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Import signed certificates into VCF Operations 9.1 (Fleet Management).")
    p.add_argument("--fqdn", help="VCF Operations FQDN")
    p.add_argument("--user", help="Username (e.g. admin)")
    p.add_argument("--report", default="certificates_report.json",
                   help="Certificate report JSON (default: certificates_report.json)")
    p.add_argument("--certs-dir", default="signed_certs",
                   help="Folder with signed certificates (default: signed_certs)")
    p.add_argument("--csr-dir", default="csrs_generated",
                   help="Folder with the generated CSRs, used for key matching (default: csrs_generated)")
    p.add_argument("--chain", nargs="*", default=[],
                   help="PEM file(s) with intermediate and root CA certificates")
    p.add_argument("--allow-no-chain", action="store_true",
                   help="Allow running without --chain (only for self-signed leaf certificates)")
    p.add_argument("--ca-type", default="EXTERNAL_CA", choices=VALID_CA_TYPES,
                   help="caType sent to the API (default: EXTERNAL_CA)")
    p.add_argument("--only", nargs="+",
                   help="Only process components whose FQDN contains any of these texts")
    p.add_argument("--exclude", nargs="+",
                   help="Skip components whose FQDN contains any of these texts")
    p.add_argument("--port", type=int, default=443,
                   help="TLS port used to read the served certificate (default 443)")
    p.add_argument("--force", action="store_true",
                   help="Replace even if the component already serves the signed certificate")
    p.add_argument("--stop-on-failure", action="store_true",
                   help="Stop the run at the first failed component")
    p.add_argument("--dry-run", action="store_true",
                   help="Match and pre-check only; change nothing and do not log in")
    p.add_argument("--no-precheck", action="store_true",
                   help="Skip openssl pre-checks (not recommended)")
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    p.add_argument("--interval", type=int, default=10, help="Seconds between status checks (default 10)")
    p.add_argument("--timeout", type=int, default=1800, help="Max seconds per workflow (default 1800)")
    p.add_argument("--ca-bundle", help="CA bundle to enable TLS verification of the VCF Operations API "
                                       "(default: disabled, lab use)")
    return p.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.report):
        print(f"[-] File '{args.report}' not found. Run the certificate report script first.")
        sys.exit(1)
    if not os.path.isdir(args.certs_dir):
        print(f"[-] Folder '{args.certs_dir}' not found. Put the signed certificates there.")
        sys.exit(1)

    with open(args.report, "r", encoding="utf-8") as f:
        report = json.load(f)
    candidates = [c for c in report.get("vcfCertificateModels", [])
                  if c.get("category") not in SKIP_CATEGORIES
                  and c.get("certificateResourceKey") and c.get("applianceFqdn")]
    if not candidates:
        print("[-] No replaceable certificates found in the report.")
        sys.exit(1)

    # CA chain (intermediates + root)
    chain_blocks = []
    for path in args.chain:
        blocks = read_pem_blocks(path)
        if not blocks:
            print(f"[-] No PEM certificates found in chain file '{path}'.")
            sys.exit(1)
        chain_blocks.extend(blocks)
    print(f"[*] CA chain: {len(chain_blocks)} certificate(s) loaded.")
    if not chain_blocks and not args.allow_no_chain and not args.dry_run:
        print("[-] No CA chain supplied. Use --chain <file> with the intermediate/root CA certificates.")
        sys.exit(1)

    openssl_ok = have_openssl() and not args.no_precheck
    if not openssl_ok:
        print("[!] openssl pre-checks are disabled or openssl is not installed.")

    files = sorted(os.path.join(args.certs_dir, n) for n in os.listdir(args.certs_dir)
                   if n.lower().endswith(CERT_EXTENSIONS))
    if not files:
        print(f"[-] No {CERT_EXTENSIONS} files in '{args.certs_dir}'.")
        sys.exit(1)

    # --- Match files to managed certificates and pre-check them ---
    plan, skipped = {}, []
    for path in files:
        name = os.path.basename(path)
        stem = os.path.splitext(name)[0]
        blocks = read_pem_blocks(path)
        if not blocks:
            skipped.append((name, "no PEM certificate found (DER/P7B are not supported; convert with openssl)"))
            continue
        leaf, extra = blocks[0], blocks[1:]
        info = cert_info(leaf) if openssl_ok else None

        entry, why = match_entry(stem, info, candidates)
        if not entry:
            skipped.append((name, why))
            continue
        if not name_selected(entry["applianceFqdn"], args.only, args.exclude):
            continue

        cert_id = entry["certificateResourceKey"]
        if cert_id in plan:
            skipped.append((name, f"duplicate: {plan[cert_id]['file']} already matches this component"))
            continue

        problems, warnings = [], []
        if openssl_ok:
            csr_path = os.path.join(args.csr_dir, safe_name(
                entry.get("appliance", "UNKNOWN"), entry["applianceFqdn"], cert_id) + ".csr")
            problems, warnings = precheck(leaf, extra + chain_blocks, info, entry, csr_path)

        plan[cert_id] = {
            "file": name, "entry": entry, "problems": problems, "warnings": warnings,
            "chain": build_chain(leaf, extra, chain_blocks),
            "fp": fingerprint_of_pem(leaf), "serial": cert_serial(leaf),
            "installed": False,
        }

    # --- Installed-check: does the component already serve this exact certificate? ---
    if not args.force:
        print("[*] Checking which components already serve the signed certificate...")
        for p in plan.values():
            if p["problems"] or not p["fp"]:
                continue
            served = served_cert_fingerprint(p["entry"]["applianceFqdn"], args.port)
            if served is None:
                p["warnings"].append(
                    f"could not read the certificate served on port {args.port}; installed-check skipped")
            elif served == p["fp"]:
                p["installed"] = True

    # --- Show the plan ---
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
        if p["installed"] and not p["problems"]:
            serial = f" (serial {p['serial']})" if p["serial"] else ""
            print(f"      [=] Certificate already installed{serial}; skipping.")
    for name, why in skipped:
        print(f"{'(skipped)':<24} {name:<36} {why}")
    print("=" * 110)

    ready = [p for p in items if not p["problems"] and not p["installed"]]
    installed = [p for p in items if p["installed"] and not p["problems"]]
    blocked = [p for p in items if p["problems"]]
    print(f"[*] {len(ready)} ready, {len(installed)} already installed, "
          f"{len(blocked)} blocked, {len(skipped)} skipped.")

    if args.dry_run:
        print("[*] Dry run: nothing was changed.")
        return
    if not ready:
        if installed and not blocked:
            print("[*] Nothing to do: all matching certificates are already installed.")
        else:
            print("[-] Nothing to import.")
        sys.exit(1 if (blocked or not installed) else 0)

    if not args.yes:
        print("\n[!] Replacing a certificate restarts services on that component.")
        print("    VCF_OPERATIONS (if included) is processed last.")
        if input("    Type 'yes' to continue: ").strip().lower() != "yes":
            print("[*] Cancelled.")
            return

    # --- Connect ---
    fqdn = args.fqdn or input("\n  VCF Operations FQDN: ").strip()
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

    success, failures = 0, 0
    failed_list, unverified_list, not_processed = [], [], []
    total = len(ready)

    try:
        print(f"\n[*] Replacing {total} certificate(s)...")
        print("=" * 110)
        for idx, p in enumerate(ready, start=1):
            if args.stop_on_failure and failures:
                not_processed.append(f"{p['entry'].get('appliance', 'UNKNOWN')} ({p['entry']['applianceFqdn']})")
                continue

            e = p["entry"]
            cert_id = e["certificateResourceKey"]
            host = e["applianceFqdn"]
            label = f"{e.get('appliance', 'UNKNOWN')} ({host})"
            print(f"[{idx}/{total}] Replacing certificate for {label}")
            print(f"    -> file={p['file']}  certificateId={cert_id}  caType={args.ca_type}")

            result = replace_certificate(session, fqdn, token, cert_id, args.ca_type, p["chain"])
            if not (result and result.get("requestId")):
                print(f"    [-] Could not launch the workflow for {label}.")
                failures += 1
                failed_list.append(label)
                continue

            request_id = result["requestId"]
            print(f"    [+] Workflow launched. RequestId: {request_id}")

            state, status = wait_for_workflow(session, fqdn, token, request_id,
                                              args.timeout, args.interval)
            if state in ("COMPLETED", "SUCCESSFUL"):
                print(f"    [+] Workflow completed for {label}.")
                if p["fp"]:
                    outcome = verify_served(host, args.port, p["fp"])
                    if outcome == "VERIFIED":
                        print(f"    [+] Verified: {host}:{args.port} now serves the signed certificate.")
                        success += 1
                    elif outcome == "MISMATCH":
                        print(f"    [-] The workflow completed but {host}:{args.port} still serves a "
                              f"different certificate. Check the VCF Operations UI.")
                        failures += 1
                        failed_list.append(f"{label} [VERIFY MISMATCH]")
                    else:
                        print(f"    [!] Could not connect to {host}:{args.port} to verify "
                              f"(the service may still be restarting).")
                        success += 1
                        unverified_list.append(label)
                else:
                    success += 1
            else:
                print(f"    [-] Workflow ended with state {state}.")
                if status:
                    print(json.dumps(status, indent=2))
                if state in ("UNKNOWN", "TIMEOUT"):
                    print("        Verify the result in the VCF Operations UI before retrying.")
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
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()