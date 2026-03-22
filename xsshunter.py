#!/usr/bin/env python3
"""
XSS Hunter v2.0 - Automated Reflected XSS Finding Tool
Bug Bounty Automation Script
- Live progress bar dalfox ke liye
- Auto internet check + wait
- Error logging file mein
- Better timeout defaults
- Auto resume if stuck
"""

import os
import subprocess
import sys
import re
import shutil
import concurrent.futures
import requests
import threading
import argparse
import time
import signal
import logging
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════╗
║         XSS HUNTER v2.0 - Bug Bounty         ║
║     Automated Reflected XSS Scanner          ║
║     Live Progress + Auto Resume + Clean!     ║
║                                              ║
║         Created by EnCrYpTeD05               ║
╚══════════════════════════════════════════════╝
{RESET}
""")

def info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def success(msg): print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def error(msg):   print(f"{RED}[X]{RESET} {msg}")

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
def setup_logging():
    log_file = f"xss_hunter_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.ERROR,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    info(f"Error log file: {log_file}")
    return log_file

# ─────────────────────────────────────────────
# INTERNET CHECK
# ─────────────────────────────────────────────
def check_internet():
    # Multiple servers check karo — ek bhi respond kare toh internet hai
    test_hosts = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    for host in test_hosts:
        try:
            import socket
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 53))
            return True
        except:
            continue
    return False

def wait_for_internet():
    if check_internet():
        return
    warn("Internet disconnected! Waiting for reconnection...")
    dots = 0
    while not check_internet():
        dots = (dots % 3) + 1
        print(f"\r{YELLOW}[!]{RESET} Checking{'.' * dots}   ", end="", flush=True)
        time.sleep(2)
    print()
    success("Internet reconnected! Continuing...")

# ─────────────────────────────────────────────
# SIGNAL HANDLER — Ctrl+C gracefully handle
# ─────────────────────────────────────────────
def handle_interrupt(sig, frame):
    print(f"\n\n{YELLOW}[!]{RESET} Script terminated by user!")
    print(f"{CYAN}[*]{RESET} All progress has been saved.")
    print(f"{CYAN}[*]{RESET} Check results with:")
    print(f"    cat scan | grep -E '\\[POC\\]|\\[W\\]'")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

# ─────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────
def print_progress(current, total, prefix="Progress", bar_len=35):
    if total == 0:
        return
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    percent = current / total * 100
    print(f"\r{CYAN}{prefix}:{RESET} |{bar}| {percent:.1f}% ({current}/{total})", end="", flush=True)

# ─────────────────────────────────────────────
# STEP 1: SUBDOMAIN FINDING (subfinder)
# ─────────────────────────────────────────────
def find_subdomains(domain, output_file="subdomains.txt"):
    info(f"Finding subdomains for: {domain}")

    if not shutil.which("subfinder"):
        error("subfinder is not installed!")
        error("Install it: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        sys.exit(1)

    wait_for_internet()

    try:
        subprocess.run(
            ["subfinder", "-d", domain, "-o", output_file, "-silent"],
            capture_output=True, text=True, timeout=120
        )
    except subprocess.TimeoutExpired:
        warn("Subfinder timed out, moving on...")
        logging.error("Subfinder timeout expired")

    if os.path.exists(output_file):
        with open(output_file) as f:
            count = len([l for l in f.readlines() if l.strip()])
        if count > 0:
            success(f"{count} subdomains found! -> {output_file}")
            return True, output_file
        else:
            warn("No subdomains found.")
            return False, None
    else:
        error("Subfinder output file was not created.")
        logging.error("Subfinder output file missing")
        return False, None


# ─────────────────────────────────────────────
# STEP 2: ACTIVE SUBDOMAIN CHECK
# ─────────────────────────────────────────────
checked_count = 0
lock = threading.Lock()

def check_domain(domain):
    global checked_count
    domain = domain.strip()
    if not domain:
        return None
    url = f"http://{domain}"
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        result = domain if response.status_code == 200 else None
    except:
        result = None
    with lock:
        checked_count += 1
    return result

def find_active_subdomains(input_file="subdomains.txt", output_file="activesubdomains.txt", threads=20):
    global checked_count
    checked_count = 0
    info(f"Checking active subdomains ({threads} threads)...")

    try:
        with open(input_file) as f:
            domains = [l.strip() for l in f.readlines() if l.strip()]
    except FileNotFoundError:
        error(f"File not found: {input_file}")
        sys.exit(1)

    total = len(domains)
    info(f"Total {total} subdomains to check...")
    active_list = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_domain, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            done += 1
            print_progress(done, total, prefix="Active Check")
            if result:
                active_list.append(result)

    print()

    with open(output_file, "w") as f:
        for d in active_list:
            f.write(d + "\n")

    success(f"{len(active_list)} active subdomains found! -> {output_file}")
    return output_file


# ─────────────────────────────────────────────
# STEP 3: PARAMETER FINDING (paramspider)
# ─────────────────────────────────────────────
def find_parameters(domain, has_subdomains, active_file="activesubdomains.txt"):
    info("Finding parameters using ParamSpider...")

    if not shutil.which("paramspider"):
        error("paramspider is not installed! Install it: pip install paramspider")
        sys.exit(1)

    wait_for_internet()

    info("ParamSpider is running — no timeout, all parameters will be collected...")

    # Spinner thread — ParamSpider chal raha hai dikhao
    spinner_running = threading.Event()
    spinner_running.set()

    def spinner_thread():
        chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        collected = 0
        while spinner_running.is_set():
            # Results folder mein parameters count karo live
            try:
                results_dir = Path("results")
                if results_dir.exists():
                    total = 0
                    for f in results_dir.glob("*.txt"):
                        with open(f) as rf:
                            total += len([l for l in rf.readlines() if l.strip()])
                    collected = total
            except:
                pass
            print(f"\r{CYAN}[*]{RESET} ParamSpider collecting... {chars[i % len(chars)]} | Parameters found so far: {GREEN}{collected}{RESET}   ", end="", flush=True)
            i += 1
            time.sleep(0.2)
        print()

    t = threading.Thread(target=spinner_thread, daemon=True)
    t.start()

    if has_subdomains and os.path.exists(active_file):
        subprocess.run(
            ["paramspider", "-l", active_file],
            text=True
        )
        spinner_running.clear()
        t.join()
        info(f"Using active subdomains list: {active_file}")
    else:
        subprocess.run(
            ["paramspider", "-d", domain],
            text=True
        )
        spinner_running.clear()
        t.join()
        info(f"Using direct domain: {domain}")

    results_dir = Path("results")
    if not results_dir.exists():
        error("ParamSpider results/ folder was not created.")
        logging.error("ParamSpider results/ folder missing")
        sys.exit(1)

    txt_files = list(results_dir.glob("*.txt"))
    if not txt_files:
        error("ParamSpider did not generate any output file.")
        sys.exit(1)

    merged_file = "parameters.txt"
    with open(merged_file, "w") as outfile:
        for txt in txt_files:
            with open(txt) as infile:
                outfile.write(infile.read())

    with open(merged_file) as f:
        total = len([l for l in f.readlines() if l.strip()])

    success(f"{total} parameters found (merged)! -> {merged_file}")
    return merged_file


# ─────────────────────────────────────────────
# STEP 4: SINGLE PARAMETER FILTER
# ─────────────────────────────────────────────
def filter_single_params(input_file="parameters.txt", output_file="singleparam.txt"):
    info("Filtering single parameter URLs...")

    single_params = []
    try:
        with open(input_file) as f:
            lines = f.readlines()
    except FileNotFoundError:
        error(f"File not found: {input_file}")
        sys.exit(1)

    total = len(lines)
    for i, line in enumerate(lines):
        print_progress(i + 1, total, prefix="Filtering ")
        line = line.strip()
        if "?" not in line:
            continue
        parts = line.split("?", 1)
        if len(parts) < 2:
            continue
        query = parts[1]
        if "&" not in query:
            # Skip URLs containing account or login keywords
            if "account" in line.lower() or "login" in line.lower():
                continue
            single_params.append(line)

    print()

    with open(output_file, "w") as f:
        for url in single_params:
            f.write(url + "\n")

    success(f"{len(single_params)} single-parameter URLs found! -> {output_file}")
    return output_file


# ─────────────────────────────────────────────
# STEP 5: REPLACE FUZZ WITH 123
# ─────────────────────────────────────────────
def replace_fuzz(input_file="singleparam.txt", output_file="withoutfuzz.txt"):
    info("Replacing FUZZ with 123...")

    try:
        with open(input_file) as f:
            lines = f.readlines()
    except FileNotFoundError:
        error(f"File not found: {input_file}")
        sys.exit(1)

    replaced = []
    seen = set()
    dupes = 0
    for line in lines:
        line = line.strip()
        new_line = re.sub(r'FUZZ', '123', line, flags=re.IGNORECASE)
        if new_line in seen:
            dupes += 1
            continue
        seen.add(new_line)
        replaced.append(new_line)

    with open(output_file, "w") as f:
        for url in replaced:
            f.write(url + "\n")

    success(f"FUZZ replaced successfully! -> {output_file}")
    if dupes > 0:
        warn(f"{dupes} duplicate URLs removed!")
    return output_file


# ─────────────────────────────────────────────
# STEP 6: DALFOX — Live Progress + Auto Resume
# ─────────────────────────────────────────────
def run_dalfox(input_file="withoutfuzz.txt", output_file="scan", dalfox_mode="default", workers=5, delay=500, timeout=30):
    info(f"Starting Dalfox scan...")
    info(f"Settings: workers={workers}, delay={delay}ms, timeout={timeout}s")

    if not shutil.which("dalfox"):
        error("dalfox is not installed! Install it: go install github.com/hahwul/dalfox/v2@latest")
        sys.exit(1)

    # Resume: skip already scanned URLs
    resume_file = "scanned_urls.txt"
    scanned_urls = set()
    if os.path.exists(resume_file):
        with open(resume_file) as f:
            scanned_urls = set(l.strip() for l in f.readlines())
        warn(f"Resume mode ON: {len(scanned_urls)} URLs already scanned, skipping them!")

    try:
        with open(input_file) as f:
            all_urls = [l.strip() for l in f.readlines() if l.strip()]
    except FileNotFoundError:
        error(f"File not found: {input_file}")
        sys.exit(1)

    pending_urls = [u for u in all_urls if u not in scanned_urls]
    total_pending = len(pending_urls)

    if total_pending == 0:
        warn("All URLs have already been scanned!")
        return output_file

    info(f"Total {total_pending} URLs to scan...")
    print()

    url_index = 0

    while url_index < len(pending_urls):
        # Remaining URLs temp file mein
        temp_input = "pending_urls.txt"
        remaining = pending_urls[url_index:]
        with open(temp_input, "w") as f:
            for url in remaining:
                f.write(url + "\n")

        wait_for_internet()

        if dalfox_mode == "default":
            info("Dalfox running in default mode (Reflected XSS + WAF Evasion)...")
            dalfox_cmd = [
                "dalfox", "file", temp_input,
                "--mining-dom=false",
                "--skip-bav",
                "--waf-evasion",
                "-o", output_file,
                "--output-all"
            ]
        else:
            info(f"Dalfox custom mode: workers={workers}, delay={delay}ms, timeout={timeout}s")
            dalfox_cmd = [
                "dalfox", "file", temp_input,
                "--mining-dom=false",
                "--skip-bav",
                "--waf-evasion",
                "-w", str(workers),
                "--delay", str(delay),
                "--timeout", str(timeout),
                "-o", output_file,
                "--output-all"
            ]

        process = subprocess.Popen(
            dalfox_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Filter words — ye lines screen pe nahi dikhegi
        filter_words = [
            "Setting worker=",
            "for WAF-Evasion",
            "[I] Setting",
        ]

        import select as _select

        last_line_count = 0
        start_time = time.time()

        # Live output thread
        def print_output(proc):
            for line in proc.stdout:
                line = line.rstrip()
                # Filter karo spam lines
                if any(fw in line for fw in filter_words):
                    continue
                print(line)

        output_thread = threading.Thread(target=print_output, args=(process,), daemon=True)
        output_thread.start()

        while True:
            # Internet check
            if not check_internet():
                print()
                warn("Internet disconnected! Waiting...")
                process.kill()
                wait_for_internet()
                break  # restart dalfox

            # Scan file lines
            current_lines = 0
            poc_count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    lines = f.readlines()
                    current_lines = len(lines)
                    poc_count = sum(1 for l in lines if "[POC]" in l or "[W]" in l)

            # Progress track
            if current_lines != last_line_count:
                last_line_count = current_lines

            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            scanned_so_far = url_index + 1
            progress_pct = scanned_so_far / len(pending_urls) * 100

            # Status
            status = f"{GREEN}● Scanning{RESET}"

            poc_display = f"{RED}{BOLD}{poc_count}{RESET}" if poc_count > 0 else str(poc_count)

            print(
                f"\r{CYAN}[Dalfox]{RESET} {status} | "
                f"URL: {scanned_so_far}/{len(pending_urls)} ({progress_pct:.0f}%) | "
                f"Lines: {current_lines} | "
                f"POC: {poc_display} | "
                f"Time: {mins:02d}:{secs:02d}  ",
                end="", flush=True
            )

            # Rate limit detection — scan file mein 429 check karo
            if os.path.exists(output_file):
                with open(output_file) as rf:
                    scan_content = rf.read()
                    if "429" in scan_content or "rate limit" in scan_content.lower() or "too many requests" in scan_content.lower():
                        print(f"\n{YELLOW}[!]{RESET} Rate limit detected! Site is blocking requests.")
                        warn("Increasing delay automatically — waiting 30 seconds...")
                        process.kill()
                        time.sleep(30)
                        # Delay double kar do
                        delay = min(delay * 2, 2000)
                        info(f"New delay: {delay}ms — restarting scan...")
                        break

            # Process complete?
            if process.poll() is not None:
                url_index = len(pending_urls)  # sab ho gaye
                break

            time.sleep(1)

    print()

    # Cleanup
    if os.path.exists("pending_urls.txt"):
        os.remove("pending_urls.txt")
    if os.path.exists(resume_file):
        os.remove(resume_file)

    if os.path.exists(output_file):
        success(f"Dalfox scan complete! -> {output_file}")
    else:
        warn("Dalfox output file not created — no vulnerable URLs found.")

    return output_file


# ─────────────────────────────────────────────
# STEP 7: EXTRACT VULNERABLE URLs
# ─────────────────────────────────────────────
def extract_vulnerable(scan_file="scan", output_file="vulnerableurl.txt"):
    info("Extracting vulnerable URLs with [POC] and [W] tags...")

    if not os.path.exists(scan_file):
        warn(f"Scan file not found: {scan_file}")
        return None

    vulnerable = []
    with open(scan_file) as f:
        for line in f:
            if "[POC]" in line or "[W]" in line:
                vulnerable.append(line.strip())

    if vulnerable:
        with open(output_file, "w") as f:
            for url in vulnerable:
                f.write(url + "\n")
        success(f"{len(vulnerable)} VULNERABLE URLs found! -> {output_file}")
        print(f"\n{RED}{BOLD}{'='*60}{RESET}")
        print(f"{RED}{BOLD}  🎯 VULNERABLE URLs:{RESET}")
        print(f"{RED}{BOLD}{'='*60}{RESET}")
        for v in vulnerable:
            print(f"{RED}  {v}{RESET}")
        print(f"{RED}{BOLD}{'='*60}{RESET}\n")
    else:
        warn("No vulnerable URLs found. Better luck next time!")

    return output_file


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    banner()
    log_file = setup_logging()

    parser = argparse.ArgumentParser(description="XSS Hunter v2.0 - Automated Reflected XSS Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--threads", type=int, default=20, help="Active check threads (default: 20)")
    parser.add_argument("--workers", type=int, default=5, help="Dalfox workers (default: 5)")
    parser.add_argument("--delay", type=int, default=500, help="Dalfox delay ms (default: 500)")
    parser.add_argument("--timeout", type=int, default=30, help="Dalfox timeout seconds (default: 30)")
    parser.add_argument("--dalfox-mode", choices=["default", "custom"], default="default", help="default=dalfox ki apni settings, custom=workers/delay/timeout tu decide kare (default: default)")
    args = parser.parse_args()

    domain = args.domain

    print(f"{BOLD}Target:{RESET} {domain}")
    print(f"{BOLD}Time:  {RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'─'*45}{RESET}\n")

    # Internet check
    info("Checking internet connection...")
    wait_for_internet()
    success("Internet connection is OK!")
    print()

    try:
        has_subdomains, subdomain_file = find_subdomains(domain)
        print()

        if has_subdomains:
            active_file = find_active_subdomains(subdomain_file, threads=args.threads)
        else:
            active_file = None
        print()

        param_file = find_parameters(domain, has_subdomains, active_file or "activesubdomains.txt")
        print()

        single_file = filter_single_params(param_file)
        print()

        nofuzz_file = replace_fuzz(single_file)
        print()

        scan_file = run_dalfox(
            nofuzz_file,
            dalfox_mode=args.dalfox_mode,
            workers=args.workers,
            delay=args.delay,
            timeout=args.timeout
        )
        print()

        extract_vulnerable(scan_file)

        print(f"\n{GREEN}{BOLD}Scan complete! Check vulnerableurl.txt 🎯{RESET}")
        print(f"{CYAN}[*]{RESET} Error log: {log_file}\n")

    except Exception as e:
        error(f"Unexpected error: {e}")
        logging.exception("Unexpected error in main")
        sys.exit(1)


if __name__ == "__main__":
    main()
