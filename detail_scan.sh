#!/bin/bash

# ============================================================
#  autofuzz.sh — Multi-stage recon & parameter discovery
#  Stage 1 : Directory bruteforce
#  Stage 2 : Hidden file discovery per directory
#  Stage 3 : Parameter & method detection (Python scanner)
# ============================================================

TARGET=$1
DIR_WORDLIST="/usr/share/dirb/wordlists/common.txt"
FILE_WORDLIST="/home/kali/Desktop/skill_test1/wordlists/raft-medium-files.txt"

DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"
ALL_PATHS="FULL_URL.txt"
PARAM_REPORT="param_discovery_report.txt"

# Path to the Python param scanner (same dir as this script by default)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARAM_SCANNER="$SCRIPT_DIR/para.py"

# ── colours ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: ./autofuzz.sh <target>${NC}"
    exit 1
fi

# Ensure TARGET has no trailing slash
TARGET=$(echo "$TARGET" | sed 's/\/$//')

# ============================================================
# STAGE 1 — Directory discovery
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 1: Directory Discovery${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

echo "$TARGET" > "$DIR_FILE"

gobuster dir -u "$TARGET" -w "$DIR_WORDLIST" \
    | grep -E "Status: (200|204|301|302)" \
    | awk -v t="$TARGET" '{print t"/" $1}' >> "$DIR_FILE"

echo -e "${GREEN}[+] Found $(wc -l < "$DIR_FILE") paths. Saved to $DIR_FILE.${NC}"

# ============================================================
# STAGE 2 — Hidden file discovery per directory
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 2: Hidden File Discovery${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

echo "--- HIDDEN FILE REPORT ---" > "$RESULT_FILE"
> "$ALL_PATHS"

while read -r FULL_URL; do
    echo -e "${YELLOW}[!] Fuzzing: $FULL_URL${NC}"
    echo "--- Results for $FULL_URL ---" >> "$RESULT_FILE"

    GOBUSTER_OUTPUT=$(gobuster dir -u "$FULL_URL" -w "$FILE_WORDLIST" \
        -x php,bak,zip,txt,old \
        | grep -E "Status: (200|204|301|302)")

    echo "$GOBUSTER_OUTPUT" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"

    echo "$GOBUSTER_OUTPUT" | awk -v base="$FULL_URL" '{
        path = $1
        gsub(/^\//, "", path)
        print base "/" path
    }' >> "$ALL_PATHS"

done < "$DIR_FILE"

sort -u "$ALL_PATHS" -o "$ALL_PATHS"
echo -e "${GREEN}[+] Stage 2 done. $(wc -l < "$ALL_PATHS") unique URLs saved to $ALL_PATHS${NC}"

# ============================================================
# STAGE 3 — Parameter & method discovery (Python scanner)
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 3: Parameter & Method Detection${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

# Pre-flight checks
if [ ! -f "$PARAM_SCANNER" ]; then
    echo -e "${RED}[!] para.py not found at: $PARAM_SCANNER${NC}"
    echo -e "${RED}    Place para.py in the same directory as autofuzz.sh${NC}"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] python3 not found. Please install it.${NC}"
    exit 1
fi

# Check required Python libs
python3 -c "import requests, bs4" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Missing Python dependencies. Installing...${NC}"
    pip3 install requests beautifulsoup4 --quiet
fi

# Write report header
{
    echo "--- PARAMETER DISCOVERY REPORT ---"
    echo "Generated: $(date)"
    echo "Target   : $TARGET"
    echo ""
} > "$PARAM_REPORT"

echo -e "${YELLOW}[~] Handing off to para.py...${NC}"
echo -e "${YELLOW}    Input : $ALL_PATHS ($(wc -l < "$ALL_PATHS") URLs)${NC}"
echo -e "${YELLOW}    Report: $PARAM_REPORT${NC}\n"

python3 "$PARAM_SCANNER" "$ALL_PATHS" "$PARAM_REPORT"

# ============================================================
# STAGE 4 — Vulnerability scanning from param report
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 4: Vulnerability Scanning${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

VULN_SCANNER="$SCRIPT_DIR/vuln_scan.py"

if [ ! -f "$VULN_SCANNER" ]; then
    echo -e "${RED}[!] vuln_scan.py not found at: $VULN_SCANNER${NC}"
    echo -e "${RED}    Place it in the same directory as autofuzz.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}[~] Handing off to vuln_scan.py...${NC}"
echo -e "${YELLOW}    Input : $ALL_PATHS{NC}\n"

python3 "$VULN_SCANNER" "$ALL_PATHS"

# ── Final summary ────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}    ALL STAGES COMPLETE${NC}"
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "    ${CYAN}Stage 1/2 dirs & files : $ALL_PATHS         ($(wc -l < "$ALL_PATHS") URLs)${NC}"
echo -e "    ${CYAN}Stage 3 param report   : $PARAM_REPORT${NC}"
echo -e "    ${CYAN}Stage 4 vuln results   : vuln_results/${NC}"
