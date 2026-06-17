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
import json
import uuid
import webbrowser
import contextlib
import io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
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
        format="%(asctime)s [%(levelname)s] %(message)s",
        force=True
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
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        spinner_running.clear()
        t.join()
        info(f"Using active subdomains list: {active_file}")
    else:
        subprocess.run(
            ["paramspider", "-d", domain],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
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
def run_dalfox(input_file="withoutfuzz.txt", output_file="scan", dalfox_mode="default", workers=5, delay=500, timeout=30):
    info("Starting Dalfox scan...")
    info(f"Settings: workers={workers}, delay={delay}ms, timeout={timeout}s")

    if not shutil.which("dalfox"):
        error("dalfox is not installed! Install it: go install github.com/hahwul/dalfox/v2@latest")
        sys.exit(1)

    resume_file = "scanned_urls.txt"
    scanned_urls = set()
    if os.path.exists(resume_file):
        with open(resume_file, encoding="utf-8", errors="ignore") as f:
            scanned_urls = set(l.strip() for l in f if l.strip())
        warn(f"Resume mode ON: {len(scanned_urls)} URLs already scanned, skipping them!")
    elif os.path.exists(output_file):
        os.remove(output_file)

    try:
        with open(input_file, encoding="utf-8", errors="ignore") as f:
            all_urls = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        error(f"File not found: {input_file}")
        sys.exit(1)

    pending_urls = [u for u in all_urls if u not in scanned_urls]
    total_urls = len(all_urls)

    if not pending_urls:
        warn("All URLs have already been scanned!")
        return output_file

    info(f"Total {len(pending_urls)} URLs to scan...")
    info("Dalfox resilient mode ON: one URL per run, crash-safe resume enabled.")
    print()

    filter_words = [
        "Setting worker=",
        "for WAF-Evasion",
        "[I] Setting",
    ]

    crash_count = 0
    url_index = 0

    while url_index < len(pending_urls):
        if globals().get("SHOULD_STOP_SCAN", lambda: False)():
            raise InterruptedError("Scan stopped by user.")

        current_url = pending_urls[url_index]
        temp_input = "pending_urls.txt"
        chunk_file = f"dalfox_current_{url_index + 1}.out"

        with open(temp_input, "w", encoding="utf-8") as f:
            f.write(current_url + "\n")

        if os.path.exists(chunk_file):
            os.remove(chunk_file)

        wait_for_internet()

        if dalfox_mode == "default":
            dalfox_cmd = [
                "dalfox", "file", temp_input,
                "--mining-dom=false",
                "--skip-bav",
                "--waf-evasion",
                "-o", chunk_file,
                "--output-all",
            ]
        else:
            dalfox_cmd = [
                "dalfox", "file", temp_input,
                "--mining-dom=false",
                "--skip-bav",
                "--waf-evasion",
                "-w", str(workers),
                "--delay", str(delay),
                "--timeout", str(timeout),
                "-o", chunk_file,
                "--output-all",
            ]

        scanned_so_far = len(scanned_urls) + 1
        progress_pct = scanned_so_far / total_urls * 100 if total_urls else 0
        start_time = time.time()
        captured_lines = []
        crash_detected = False
        rate_limited = False

        print(
            f"\r{CYAN}[Dalfox]{RESET} {GREEN}● Scanning{RESET} | "
            f"URL: {scanned_so_far}/{total_urls} ({progress_pct:.0f}%) | "
            f"POC: 0 | Time: 00:00  ",
            end="", flush=True,
        )

        process = subprocess.Popen(
            dalfox_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            if globals().get("SHOULD_STOP_SCAN", lambda: False)():
                process.kill()
                raise InterruptedError("Scan stopped by user.")

            line = line.rstrip()
            lower_line = line.lower()
            captured_lines.append(line)

            if "panic:" in lower_line or "fatal error:" in lower_line or "goroutine " in lower_line:
                crash_detected = True

            if "429" in lower_line or "rate limit" in lower_line or "too many requests" in lower_line:
                rate_limited = True

            if not any(fw in line for fw in filter_words):
                print()
                print(line)

            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            poc_count = sum(1 for l in captured_lines if "[POC]" in l or "[W]" in l)
            poc_display = f"{RED}{BOLD}{poc_count}{RESET}" if poc_count > 0 else str(poc_count)
            print(
                f"\r{CYAN}[Dalfox]{RESET} {GREEN}● Scanning{RESET} | "
                f"URL: {scanned_so_far}/{total_urls} ({progress_pct:.0f}%) | "
                f"POC: {poc_display} | "
                f"Time: {mins:02d}:{secs:02d}  ",
                end="", flush=True,
            )

        return_code = process.wait()

        chunk_text = ""
        if os.path.exists(chunk_file):
            with open(chunk_file, "r", encoding="utf-8", errors="ignore") as cf:
                chunk_text = cf.read()

        if chunk_text:
            with open(output_file, "a", encoding="utf-8", errors="ignore") as out:
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    out.write("\n")
                out.write(chunk_text)
        elif captured_lines:
            with open(output_file, "a", encoding="utf-8", errors="ignore") as out:
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    out.write("\n")
                out.write("\n".join(captured_lines) + "\n")

        if os.path.exists(chunk_file):
            os.remove(chunk_file)

        if rate_limited:
            print()
            warn("Rate limit detected! Increasing delay and retrying current URL...")
            delay = min(delay * 2, 3000)
            time.sleep(30)
            continue

        with open(resume_file, "a", encoding="utf-8") as rf:
            rf.write(current_url + "\n")
        scanned_urls.add(current_url)

        if crash_detected or return_code != 0:
            crash_count += 1
            print()
            warn(f"Dalfox crashed on URL {scanned_so_far}/{total_urls}; saved partial output and continuing.")
            logging.error("Dalfox crashed on URL %s with return code %s", current_url, return_code)

        url_index += 1

    print()

    if os.path.exists("pending_urls.txt"):
        os.remove("pending_urls.txt")
    if os.path.exists(resume_file):
        os.remove(resume_file)

    if os.path.exists(output_file):
        success(f"Dalfox scan complete! -> {output_file}")
        if crash_count:
            warn(f"Dalfox crashed on {crash_count} URL(s), but remaining URLs were scanned.")
    else:
        warn("Dalfox output file not created — no vulnerable URLs found.")

    return output_file


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
# -----------------------------
# WEB MODE
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
RUNS_DIR = BASE_DIR / "runs"
JOBS = {}
JOB_LOCK = threading.Lock()


class WebLogSink(io.TextIOBase):
    def __init__(self, job):
        self.job = job
        self.buffer = ""

    def write(self, text):
        if not text:
            return 0
        clean = strip_ansi(text)
        self.buffer += clean
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            append_job_log(self.job, line.rstrip())
        if clean.endswith("\r"):
            append_job_log(self.job, clean.rstrip())
            self.buffer = ""
        return len(text)

    def flush(self):
        if self.buffer.strip():
            append_job_log(self.job, self.buffer.strip())
            self.buffer = ""


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text).replace("\r", "\n")


def safe_domain(value):
    value = (value or "").strip().lower()
    value = re.sub(r"^https?://", "", value).split("/")[0]
    if not re.fullmatch(r"[a-z0-9.-]{2,253}", value) or ".." in value:
        raise ValueError("Enter a valid domain like example.com")
    return value


def job_state_path(job):
    return Path(job["dir"]) / "job_state.json"


def save_job(job):
    job["updated_at"] = datetime.now().isoformat(timespec="seconds")
    state = {k: v for k, v in job.items() if k not in {"thread", "process"}}
    job_state_path(job).write_text(json.dumps(state, indent=2), encoding="utf-8")


def public_job(job):
    return {k: v for k, v in job.items() if k not in {"thread", "process"}}


def append_job_log(job, message):
    message = message.strip()
    if not message:
        return
    stamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{stamp}] {message}"
    with JOB_LOCK:
        job["logs"].append(line)
        job["logs"] = job["logs"][-600:]
        save_job(job)
    with open(Path(job["dir"]) / "web-run.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def set_job(job, **updates):
    with JOB_LOCK:
        job.update(updates)
        save_job(job)


def should_stop(job):
    return bool(job.get("stop_requested"))


def raise_if_stopped(job):
    if should_stop(job):
        raise InterruptedError("Scan stopped by user.")


def list_artifacts(job):
    run_dir = Path(job["dir"]).resolve()
    artifacts = []
    skip = {"job_state.json"}
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.name in skip:
            continue
        rel = path.relative_to(run_dir).as_posix()
        artifacts.append({
            "name": rel,
            "size": path.stat().st_size,
            "url": f"/api/download/{job['id']}/{rel}",
        })
    return artifacts


def web_wait_for_internet(job, max_wait=75):
    if check_internet():
        return
    append_job_log(job, "Internet disconnected. Waiting before saving partial progress...")
    started = time.time()
    while time.time() - started < max_wait:
        raise_if_stopped(job)
        if check_internet():
            append_job_log(job, "Internet reconnected. Continuing scan.")
            return
        remaining = int(max_wait - (time.time() - started))
        set_job(job, status="waiting", message=f"Internet down. Retrying for {remaining}s.")
        time.sleep(3)
    set_job(job, status="paused", message="Internet did not return. Partial progress saved.")
    raise ConnectionError("Internet did not return in time; partial progress saved.")


def run_web_scan_job(job_id):
    job = JOBS[job_id]
    config = job["config"]
    run_dir = Path(job["dir"])
    old_cwd = Path.cwd()
    original_wait = globals()["wait_for_internet"]
    original_popen = subprocess.Popen
    original_stop_check = globals().get("SHOULD_STOP_SCAN", lambda: False)
    globals()["wait_for_internet"] = lambda: web_wait_for_internet(job)
    globals()["SHOULD_STOP_SCAN"] = lambda: should_stop(job)

    def tracked_popen(*args, **kwargs):
        proc = original_popen(*args, **kwargs)
        with JOB_LOCK:
            job["process"] = proc
        return proc

    def step(name, progress):
        raise_if_stopped(job)
        set_job(job, status="running", step=name, progress=progress, artifacts=list_artifacts(job))
        append_job_log(job, f"== {name} ==")

    try:
        os.chdir(run_dir)
        subprocess.Popen = tracked_popen
        sink = WebLogSink(job)
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            banner()
            log_file = setup_logging()
            domain = config["domain"]
            print(f"Target: {domain}")
            print(f"Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            step("Checking internet", 5)
            web_wait_for_internet(job)
            raise_if_stopped(job)
            success("Internet connection is OK!")

            step("Finding subdomains", 15)
            has_subdomains, subdomain_file = find_subdomains(domain)
            raise_if_stopped(job)

            active_file = None
            if has_subdomains:
                step("Checking active subdomains", 30)
                active_file = find_active_subdomains(subdomain_file, threads=config["threads"])
                raise_if_stopped(job)

            step("Finding parameters", 45)
            param_file = find_parameters(domain, has_subdomains, active_file or "activesubdomains.txt")
            raise_if_stopped(job)

            step("Filtering single parameters", 60)
            single_file = filter_single_params(param_file)
            raise_if_stopped(job)

            step("Replacing FUZZ markers", 70)
            nofuzz_file = replace_fuzz(single_file)
            raise_if_stopped(job)

            step("Running Dalfox", 85)
            scan_file = run_dalfox(
                nofuzz_file,
                dalfox_mode=config["dalfox_mode"],
                workers=config["workers"],
                delay=config["delay"],
                timeout=config["timeout"],
            )
            raise_if_stopped(job)

            step("Extracting vulnerable URLs", 95)
            extract_vulnerable(scan_file)
            success(f"Scan finished. Error log: {log_file}")

        set_job(job, status="completed", step="Finished", progress=100, message="Scan finish.", artifacts=list_artifacts(job))
    except InterruptedError:
        append_job_log(job, "Scan stopped by user.")
        set_job(job, status="stopped", step="Stopped By User", message="Stopped by user.", artifacts=list_artifacts(job))
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        set_job(job, status="failed", message=f"Scanner stopped with exit code {code}.", artifacts=list_artifacts(job))
        append_job_log(job, f"Scanner stopped with exit code {code}.")
    except ConnectionError as e:
        append_job_log(job, str(e))
        set_job(job, status="paused", artifacts=list_artifacts(job))
    except Exception as e:
        logging.exception("Unexpected error in web scan")
        set_job(job, status="failed", message=str(e), artifacts=list_artifacts(job))
        append_job_log(job, f"Unexpected error: {e}")
    finally:
        globals()["wait_for_internet"] = original_wait
        globals()["SHOULD_STOP_SCAN"] = original_stop_check
        subprocess.Popen = original_popen
        with JOB_LOCK:
            job["process"] = None
        os.chdir(old_cwd)


class XSSHunterWebHandler(BaseHTTPRequestHandler):
    server_version = "XSSHunterWeb/1.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def serve_file(self, path, content_type):
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/":
            self.serve_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
            return
        if route == "/styles.css":
            self.serve_file(WEB_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if route == "/app.js":
            self.serve_file(WEB_DIR / "app.js", "application/javascript; charset=utf-8")
            return
        if route == "/api/jobs":
            with JOB_LOCK:
                data = [public_job(job) for job in JOBS.values()]
            self.send_json({"jobs": data})
            return
        if route.startswith("/api/status/"):
            job_id = route.rsplit("/", 1)[-1]
            job = JOBS.get(job_id)
            if not job:
                self.send_json({"error": "Job not found"}, 404)
                return
            with JOB_LOCK:
                job["artifacts"] = list_artifacts(job)
                data = public_job(job)
            self.send_json(data)
            return
        if route.startswith("/api/download/"):
            parts = route.split("/", 4)
            if len(parts) < 5:
                self.send_error(404)
                return
            job_id, rel = parts[3], parts[4]
            job = JOBS.get(job_id)
            if not job:
                self.send_error(404)
                return
            run_dir = Path(job["dir"]).resolve()
            file_path = (run_dir / rel).resolve()
            if run_dir not in file_path.parents or not file_path.is_file():
                self.send_error(404)
                return
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/stop/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            job = JOBS.get(job_id)
            if not job:
                self.send_json({"error": "Job not found"}, 404)
                return
            with JOB_LOCK:
                job["stop_requested"] = True
                proc = job.get("process")
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    time.sleep(0.5)
                    if proc.poll() is None:
                        proc.kill()
                except Exception as e:
                    append_job_log(job, f"Stop signal warning: {e}")
            set_job(job, status="stopped", step="Stopped By User", message="Stopped by user.", artifacts=list_artifacts(job))
            append_job_log(job, "Stop requested from web dashboard.")
            self.send_json({"ok": True})
            return

        if parsed.path.startswith("/api/resume/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            job = JOBS.get(job_id)
            if not job:
                self.send_json({"error": "Job not found"}, 404)
                return
            with JOB_LOCK:
                if any(j.get("status") in {"queued", "running", "waiting"} for j in JOBS.values()):
                    self.send_json({"error": "A scan is already running."}, 409)
                    return
                job["stop_requested"] = False
                job["status"] = "queued"
                job["step"] = "Queued"
                job["message"] = "Resume queued."
                save_job(job)
                thread = threading.Thread(target=run_web_scan_job, args=(job_id,), daemon=True)
                job["thread"] = thread
                thread.start()
            append_job_log(job, "Resume requested from web dashboard.")
            self.send_json({"job_id": job_id})
            return

        if parsed.path != "/api/scan":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            domain = safe_domain(payload.get("domain"))
            config = {
                "domain": domain,
                "threads": max(1, min(int(payload.get("threads", 20)), 100)),
                "workers": max(1, min(int(payload.get("workers", 5)), 50)),
                "delay": max(0, min(int(payload.get("delay", 500)), 10000)),
                "timeout": max(5, min(int(payload.get("timeout", 30)), 180)),
                "dalfox_mode": payload.get("dalfox_mode", "default") if payload.get("dalfox_mode") in {"default", "custom"} else "default",
            }
            with JOB_LOCK:
                if any(j.get("status") in {"queued", "running", "waiting"} for j in JOBS.values()):
                    self.send_json({"error": "A scan is already running. Wait for it to finish or pause."}, 409)
                    return
                job_id = uuid.uuid4().hex[:12]
                run_dir = RUNS_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{domain}_{job_id}"
                run_dir.mkdir(parents=True, exist_ok=True)
                job = {
                    "id": job_id,
                    "created_at": datetime.now().isoformat(timespec="seconds"),
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                    "dir": str(run_dir),
                    "config": config,
                    "status": "queued",
                    "step": "Queued",
                    "progress": 0,
                    "message": "Scan queued.",
                    "logs": [],
                    "artifacts": [],
                    "stop_requested": False,
                }
                JOBS[job_id] = job
                save_job(job)
                thread = threading.Thread(target=run_web_scan_job, args=(job_id,), daemon=True)
                job["thread"] = thread
                thread.start()
            self.send_json({"job_id": job_id})
        except ValueError as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)


def load_saved_jobs():
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    for state_file in RUNS_DIR.glob("*/job_state.json"):
        try:
            job = json.loads(state_file.read_text(encoding="utf-8"))
            job["thread"] = None
            job["process"] = None
            if job.get("status") in {"queued", "running", "waiting"}:
                job["status"] = "stopped"
                job["step"] = "Stopped By User"
                job["message"] = "Stopped by user."
                job["stop_requested"] = True
            job["artifacts"] = list_artifacts(job)
            JOBS[job["id"]] = job
            save_job(job)
        except Exception:
            continue


def launch_web(host="127.0.0.1", port=8787):
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    if not (WEB_DIR / "index.html").exists():
        error("Web assets missing. Make sure web/index.html, web/styles.css and web/app.js exist.")
        sys.exit(1)
    load_saved_jobs()
    server = None
    selected_port = port
    for candidate in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, candidate), XSSHunterWebHandler)
            selected_port = candidate
            break
        except OSError:
            continue
    if server is None:
        error(f"No free web port found from {port} to {port + 19}.")
        sys.exit(1)
    url = f"http://{host}:{selected_port}"
    success(f"XSS Hunter web interface running at {url}")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        warn("Web server stopped.")
    finally:
        server.server_close()


def launch_web_background(host="127.0.0.1", port=8787):
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--web-server",
        "--host",
        host,
        "--port",
        str(port),
    ]
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    success(f"XSS Hunter web started in background: http://{host}:{port}")
    info("Terminal is free now. Web logs stay inside the dashboard.")


def main():
    parser = argparse.ArgumentParser(description="XSS Hunter v2.0 - Automated Reflected XSS Scanner")
    parser.add_argument("--web", action="store_true", help="Launch the local web dashboard")
    parser.add_argument("--web-server", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host", default="127.0.0.1", help="Web dashboard host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Web dashboard port (default: 8787)")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--threads", type=int, default=20, help="Active check threads (default: 20)")
    parser.add_argument("--workers", type=int, default=5, help="Dalfox workers (default: 5)")
    parser.add_argument("--delay", type=int, default=500, help="Dalfox delay ms (default: 500)")
    parser.add_argument("--timeout", type=int, default=30, help="Dalfox timeout seconds (default: 30)")
    parser.add_argument("--dalfox-mode", choices=["default", "custom"], default="default", help="default=dalfox ki apni settings, custom=workers/delay/timeout tu decide kare (default: default)")
    args = parser.parse_args()

    if args.web_server:
        launch_web(args.host, args.port)
        return

    if args.web:
        launch_web_background(args.host, args.port)
        return

    if not args.domain:
        parser.error("the following arguments are required for CLI mode: -d/--domain")

    banner()
    log_file = setup_logging()

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
