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
MAGENTA = "\033[35m"
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


def read_urls(path: Path) -> list[str]:
    if not path.exists():
        print(c(f"[!] Input file not found: {path}", RED))
        sys.exit(1)

    seen = set()
    urls: list[str] = []

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(("http://", "https://")):
            continue
        if line not in seen:
            seen.add(line)
            urls.append(line)

    return urls


def normalize_base_url(url: str) -> str:
    """
    Convert a discovered URL into a 'base' URL for Nikto.
    Examples:
      http://host/a/b.php   -> http://host/a/
      http://host/admin     -> http://host/
      http://host/app/      -> http://host/app/
    """
    parsed = urlsplit(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    path = parsed.path or "/"

    if not path.startswith("/"):
        path = "/" + path

    # If it looks like a file or endpoint, trim to parent directory
    if path != "/" and not path.endswith("/"):
        last_segment = path.rsplit("/", 1)[-1]
        if "." in last_segment:
            path = path.rsplit("/", 1)[0] + "/"
            if path == "":
                path = "/"
        else:
            # treat /admin as site root
            path = "/"

    return urlunsplit((scheme, netloc, path, "", ""))


def unique_preserve(items: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def run_command(
    title: str,
    cmd: list[str],
    log_path: Path,
    target: str,
    index: int,
    total: int,
) -> int:
    """
    Stream command output to screen and save a full log.
    """
    header = f"[{index}/{total}] {title} :: {target}"
    print(f"\n{c('┌' + '─' * (len(header) + 2) + '┐', CYAN)}")
    print(c(f"│ {header} │", BOLD + CYAN))
    print(c("└" + "─" * (len(header) + 2) + "┘", CYAN))
    print(c(f"[cmd] {' '.join(shlex.quote(x) for x in cmd)}", DIM))

    start = time.time()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        log_file.write(f"Title   : {title}\n")
        log_file.write(f"Target  : {target}\n")
        log_file.write(f"Started : {datetime.now().isoformat(sep=' ', timespec='seconds')}\n")
        log_file.write(f"Command : {' '.join(shlex.quote(x) for x in cmd)}\n")
        log_file.write("\n" + "=" * 80 + "\n\n")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert proc.stdout is not None

        for line in proc.stdout:
            log_file.write(line)
            # Keep output tidy: show the tool output indented
            if line.strip():
            	print(c("│ ", CYAN) + line.rstrip())

        return_code = proc.wait()

        duration = time.time() - start
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write(f"Finished: {datetime.now().isoformat(sep=' ', timespec='seconds')}\n")
        log_file.write(f"ExitCode: {return_code}\n")
        log_file.write(f"Duration: {duration:.2f}s\n")

    if return_code == 0:
        print(c(f"[+] Completed in {duration:.2f}s -> {log_path}", GREEN))
    else:
        print(c(f"[!] Finished with exit code {return_code} in {duration:.2f}s -> {log_path}", YELLOW))

    return return_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage 4 vulnerability scanner: Nikto on base URLs, Nuclei on full URLs."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="FULL_URL.txt",
        help="Path to FULL_URL.txt (default: FULL_URL.txt)",
    )
    parser.add_argument(
        "--out",
        default="vuln_results",
        help="Output directory (default: vuln_results)",
    )
    args = parser.parse_args()

    input_file = Path(args.input_file).resolve()
    out_dir = Path(args.out).resolve()
    nikto_dir = out_dir / "nikto"
    nuclei_dir = out_dir / "nuclei"
    summary_file = out_dir / "summary.txt"

    ensure_tool("nikto")
    ensure_tool("nuclei")

    urls = read_urls(input_file)
    if not urls:
        print(c("[!] No valid URLs found in input file.", RED))
        return 1

    full_urls = unique_preserve(urls)
    nikto_targets = unique_preserve([normalize_base_url(u) for u in full_urls])

    out_dir.mkdir(parents=True, exist_ok=True)
    nikto_dir.mkdir(parents=True, exist_ok=True)
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    summary_lines = []
    summary_lines.append("VULN SCAN SUMMARY")
    summary_lines.append(f"Generated : {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    summary_lines.append(f"Input     : {input_file}")
    summary_lines.append(f"Full URLs : {len(full_urls)}")
    summary_lines.append(f"Nikto URLs: {len(nikto_targets)}")
    summary_lines.append("")

    banner("STAGE 4 — VULNERABILITY SCANNING")

    status(f"[+] Loaded {len(full_urls)} unique full URLs from {input_file}", GREEN)
    status(f"[+] Nikto will run on {len(nikto_targets)} unique base URLs", GREEN)
    status(f"[+] Nuclei will run on {len(full_urls)} unique full URLs", GREEN)

    # ── Nikto ────────────────────────────────────────────────
    banner("NIKTO SCAN")
    nikto_failures = 0
    for i, target in enumerate(nikto_targets, start=1):
        safe_name = target.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_")
        log_path = nikto_dir / f"{i:03d}_{safe_name}.log"

        cmd = [
            "nikto",
            "-h", target,
            "-ask", "no",
            "-Tuning", "x",       
            "-Cgidirs", "all", 
        ]

        rc = run_command("Nikto", cmd, log_path, target, i, len(nikto_targets))
        summary_lines.append(f"Nikto  [{i:03d}] rc={rc} target={target} log={log_path}")
        if rc != 0:
            nikto_failures += 1

    # ── Nuclei ───────────────────────────────────────────────
    banner("NUCLEI SCAN")
    nuclei_failures = 0
    for i, target in enumerate(full_urls, start=1):
        safe_name = target.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_")
        log_path = nuclei_dir / f"{i:03d}_{safe_name}.log"

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", "low,medium,high,critical",
            "-stats",
            "-silent",
        ]

        rc = run_command("Nuclei", cmd, log_path, target, i, len(full_urls))
        summary_lines.append(f"Nuclei [{i:03d}] rc={rc} target={target} log={log_path}")
        if rc != 0:
            nuclei_failures += 1

    summary_lines.append("")
    summary_lines.append(f"Nikto failures : {nikto_failures}")
    summary_lines.append(f"Nuclei failures: {nuclei_failures}")

    summary_file.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    banner("DONE")
    print(c(f"[+] Nikto logs  : {nikto_dir}", GREEN))
    print(c(f"[+] Nuclei logs : {nuclei_dir}", GREEN))
    print(c(f"[+] Summary     : {summary_file}", GREEN))

    return 0 if (nikto_failures == 0 and nuclei_failures == 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
