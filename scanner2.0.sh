#!/bin/bash
TARGET=$1
DIR_WORDLIST="/usr/share/dirb/wordlists/common.txt"
FILE_WORDLIST="/home/kali/Desktop/skill_test1/wordlists/raft-medium-files.txt"
DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"
ALL_PATHS="FULL_URL.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: ./autofuzz.sh <target>"
    exit 1
fi

# Ensure TARGET doesn't have a trailing slash
TARGET=$(echo "$TARGET" | sed 's/\/$//') 

echo "[+] Phase 1: Finding Directories and building full URLs..."
echo "$TARGET" > "$DIR_FILE"
gobuster dir -u "$TARGET" -w "$DIR_WORDLIST" | grep -E "Status: (200|204|301|302)" | awk -v t="$TARGET" '{print t"/"$1}' >> "$DIR_FILE"
echo "[+] Found $(wc -l < "$DIR_FILE") paths. Saved to $DIR_FILE."

echo "--- HIDDEN FILE REPORT ---" > "$RESULT_FILE"
> "$ALL_PATHS"  # Clear/init the full URLs output file

# Phase 2: Loop through the full URLs
while read -r FULL_URL; do
    echo "[!] Fuzzing: $FULL_URL"
    echo "--- Results for $FULL_URL ---" >> "$RESULT_FILE"

    # Run gobuster and capture output
    GOBUSTER_OUTPUT=$(gobuster dir -u "$FULL_URL" -w "$FILE_WORDLIST" -x php,bak,zip,txt,old \
        | grep -E "Status: (200|204|301|302)")

    # Save raw results to report
    echo "$GOBUSTER_OUTPUT" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"

    # Extract just the path (first column) and build full URL
    echo "$GOBUSTER_OUTPUT" | awk -v base="$FULL_URL" '{
        path = $1
        # Remove leading slash if base already ends with something
        gsub(/^\//, "", path)
        print base "/" path
    }' >> "$ALL_PATHS"

done < "$DIR_FILE"

echo ""
echo "[+] Done! Results saved to:"
echo "    - Full report : $RESULT_FILE"
echo "    - All found URLs: $ALL_PATHS"
```

The key changes are:

**1. Capture gobuster output into a variable** — instead of piping directly to the file, it's stored in `GOBUSTER_OUTPUT` so it can be used twice (once for the report, once for URL building).

**2. URL reconstruction with `awk`** — after saving to the report, the same output is piped into `awk` which strips the leading slash from the discovered path and prepends the base directory URL, giving you clean full paths like:
```
http://target.com/admin/config.php
http://target.com/uploads/backup.zip
