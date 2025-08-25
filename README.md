⚠️ Disclaimer

This tool is for educational and authorized security testing only. I am not responsible for misuse.

-------

CacheBuster 🚀

CacheBuster is a Python tool to test for unauthenticated cache purge and cache poisoning vulnerabilities.  It automatically detects when a domain is vulnerable to `PURGE` cache attacks, attempts cache poisoning, and highlights [POSSIBLE VULN] and [CRITICAL VULN] findings.



🔥 Features
- Test single domain (`-u`) or bulk list (`-l`).
- Detects cache purge support via `PURGE` requests.
- Flags responses with `X-Cache-Hits: 1`.
- Attempts cache poisoning (`/random-path` with malformed Host headers).
- Escalation detection → marks as **CRITICAL** if poisoned content is retrievable.
- Colorized terminal output (red = vuln).
- Optional save results to:
  - `POSSIBLE_VULN.txt`
  - `CRITICAL_VULN.txt`

---

⚡ Usage

python3 cachebuster.py -u https://example.com 

python3 cachebuster.py -l domains.txt                                                                                                                                                                        


🛠 Requirements
Python 3.8+
requests
colorama

Install dependencies:
pip install requests colorama

----

📖 CacheBuster Command-Line Options

usage: CacheBuster.py [-h] [-d DOMAIN] [-l LIST] [--threads THREADS] 
 [--timeout TIMEOUT] [--insecure] [--save] 
[--save-critical] [--jsonl JSONL] [--csv CSV] 
[--user-agent USER_AGENT] [--try-origin]

🔹 -d DOMAIN, --domain DOMAIN

What it does: Tests a single target domain/URL.

✅Examples: 

python3 CacheBuster.py -d example.com     

python3 CacheBuster.py -d https://example.com

- Use case: Quick test against one target.

 🔹 -l LIST, --list LIST

What it does: Takes a file with multiple domains/URLs (one per line).

✅Example:
python3 CacheBuster.py -l domains.txt
- Use case: When scanning hundreds or thousands of domains at once.

  🔹 --threads THREADS

What it does: Runs multiple requests in parallel.

✅Example:
python3 CacheBuster.py -l domains.txt --threads 10
- Use case: Speeds up scans for large target lists. ⚠️ Too many threads can trigger WAF/CDN bans or overwhelm the server.

  --timeout TIMEOUT

What it does: Sets request timeout (in seconds).

✅Example:
python3 CacheBuster.py -d example.com --timeout 5
- Use case: Lower timeout = faster scanning, but you might miss slow servers. Default is 12s (safe balance).

  🔹 --insecure

What it does: Disables TLS/SSL verification (requests.verify=False).

✅Example:
python3 CacheBuster.py -d https://10.0.0.1 --insecure
- Use case: Testing IP-based hosts, lab environments, or targets with broken/misconfigured SSL certificates.

  🔹 --try-origin

What it does: Tries origin bypass by:

Connecting directly to the server’s IP with a Host: header. Checking subdomains like origin.example.com, real.example.com, etc.

✅Example:
python3 CacheBuster.py -d example.com --try-origin
- Use case: Some CDNs cache content differently than the origin. This may leak sensitive data not meant for the public.


✅ Quick Use Cases Summary

✅Single test: -d

✅Mass scan: -l + --threads

✅Speed vs. reliability: --timeout

✅Broken SSL labs: --insecure

✅Result saving: --save, --save-critical, --jsonl, --csv

✅Stealth mode: --user-agent

✅Deeper check: --try-origin
