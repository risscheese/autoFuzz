#!/bin/bash

TARGET=$1
DIR_WORDLIST="/usr/share/dirb/wordlists/common.txt"
FILE_WORDLIST="/home/kali/Desktop/skill_test1/wordlists/raft-medium-files.txt"

DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: ./autofuzz.sh <URL>"
    exit 1
fi



# Ensure TARGET doesn't have a trailing slash so we don't get triple slashes
TARGET=$(echo "$TARGET" | sed 's/\/$//')

echo "[+] Phase 1: Finding Directories and building full URLs..."
# This version saves the FULL URL into the file
echo "$TARGET" > "$DIR_FILE"
gobuster dir -u "$TARGET" -w "$DIR_WORDLIST" | grep -E "Status: (200|204|301|302)" | awk -v t="$TARGET" '{print t"/"$1}' >> "$DIR_FILE"

echo "[+] Found $(wc -l < "$DIR_FILE") paths. Saved to $DIR_FILE."
echo "--- HIDDEN FILE REPORT ---" > "$RESULT_FILE"

# Phase 2: Loop through the full URLs
while read -r FULL_URL; do
    echo "[!] Fuzzing: $FULL_URL"
    echo "--- Results for $FULL_URL ---" >> "$RESULT_FILE"
    
    # Since FULL_URL is already complete, we use it directly
    gobuster dir -u "$FULL_URL" -w "$FILE_WORDLIST" -x php,bak,zip,txt,old | grep -E "Status: (200|204|301|302)" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"
done < "$DIR_FILE"

echo "[+] Done! Check $RESULT_FILE for results."
