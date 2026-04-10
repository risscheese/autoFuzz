#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


# ─────────────────────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def banner(title: str) -> None:
    line = "═" * 62
    print(f"\n{c(line, CYAN)}")
    print(f"{c(title.center(62), BOLD + CYAN)}")
    print(f"{c(line, CYAN)}")


def status(msg: str, color: str = WHITE) -> None:
    print(c(msg, color))


def ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(c(f"[!] Required tool not found: {name}", RED))
        sys.exit(1)


# ─────────────────────────────────────────────────────────────
# URL Processing
# ─────────────────────────────────────────────────────────────
USELESS_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".css", ".js", ".woff", ".ttf", ".ico"
)

def is_interesting(url):
    return not url.lower().endswith(USELESS_EXT)


def clean_urls(urls):
    cleaned = set()

    for url in urls:
        parsed = urlsplit(url)
        path = parsed.path.replace("/.", "/")

        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        clean = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        cleaned.add(clean)

    return list(cleaned)


def dedupe_logic(urls):
    best = {}

    for url in urls:
        parsed = urlsplit(url)
        base = parsed.path.rstrip("/")

        if base not in best:
            best[base] = url
        else:
            if any(ext in url for ext in [".php", ".asp", ".jsp"]):
                best[base] = url

    return list(best.values())


def read_urls(path: Path) -> list[str]:
    if not path.exists():
        print(f"[!] Input file not found: {path}")
        sys.exit(1)

    seen = set()
    urls = []

    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith(("http://", "https://")) and line not in seen:
            seen.add(line)
            urls.append(line)

    return urls


def normalize_base_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path or "/"

    if path != "/" and not path.endswith("/"):
        if "." in path.split("/")[-1]:
            path = path.rsplit("/", 1)[0] + "/"
        else:
            path = "/"

    return urlunsplit((scheme, netloc, path, "", ""))


def unique_preserve(items):
    seen = set()
    result = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


# ─────────────────────────────────────────────────────────────
# Command Runner
# ─────────────────────────────────────────────────────────────
def run_command(title, cmd, log_path, target, index, total):
    print(f"\n[{index}/{total}] {title} -> {target}")

    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("w") as log:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in proc.stdout:
            log.write(line)
            print(line.strip())

        return proc.wait()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", nargs="?", default="FULL_URL.txt")
    parser.add_argument("--out", default="vuln_results")
    args = parser.parse_args()

    ensure_tool("nikto")
    ensure_tool("nuclei")

    urls = read_urls(Path(args.input_file))

    # STEP 1: Clean
    full_urls = clean_urls(urls)

    # ✅ STEP 2: FILTER (IMPORTANT)
    filtered_urls = [u for u in full_urls if is_interesting(u)]
    filtered_urls = dedupe_logic(filtered_urls)

    # STEP 3: Base URLs for Nikto
    nikto_targets = unique_preserve([normalize_base_url(u) for u in filtered_urls])

    print(f"[+] Total URLs: {len(full_urls)}")
    print(f"[+] Filtered URLs: {len(filtered_urls)}")
    print(f"[+] Nikto targets: {len(nikto_targets)}")

    out_dir = Path(args.out)
    nikto_dir = out_dir / "nikto"
    nuclei_dir = out_dir / "nuclei"

    # ── Nikto (BASE URL ONLY)
    for i, target in enumerate(nikto_targets, 1):
        log = nikto_dir / f"{i}.log"
        run_command("Nikto", ["nikto", "-h", target, "-ask", "no"], log, target, i, len(nikto_targets))

    # ── Nuclei (FILTERED URL ONLY)
    for i, target in enumerate(filtered_urls, 1):
        log = nuclei_dir / f"{i}.log"
        run_command("Nuclei", ["nuclei", "-u", target, "-severity", "medium,high,critical"], log, target, i, len(filtered_urls))


if __name__ == "__main__":
    main()
