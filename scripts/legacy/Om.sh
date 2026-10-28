#!/bin/bash

# OM - Automated Reconnaissance Tool (Enhanced Version)
# Author: Major_ADI
# Updated: 2025

# Color Codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Banner
echo -e "${CYAN}"
echo " ██████╗ ███╗   ███╗  "
echo "██╔═══██╗████╗ ████║ "
echo "██║   ██║██╔████╔██║ "
echo "██║   ██║██║╚██╔╝██║ "
echo "╚██████╔╝██║ ╚═╝ ██║ "
echo " ╚═════╝ ╚═╝     ╚═╝ "
echo -e "${RESET}"
echo -e "${GREEN}Welcome to OM - Automated Reconnaissance Tool${RESET}\n"

# Tool Check Function
check_tools() {
    for tool in nmap amass whatweb dnsrecon sublist3r theHarvester gobuster sslscan wafw00f cmseek zip; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[ERROR] $tool not found. Attempting to install...${RESET}"
            sudo apt install -y $tool || pip install $tool || echo -e "${RED}[FAILED] Install $tool manually.${RESET}"
        fi
    done
}
check_tools

# Input Target
target=""
while [[ -z "$target" ]]; do
    read -p "Enter the target domain (example.com): " target
    [[ -z "$target" ]] && echo -e "${RED}[ERROR] Target cannot be empty.${RESET}"
done

# Create Base Directory
BASE_DIR="OM_Recon_${target}_$(date +%F_%T)"
mkdir -p "$BASE_DIR"
LOG_FILE="$BASE_DIR/recon_log.txt"

# Log Function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function Templates
create_folder() {
    folder=$1
    mkdir -p "$BASE_DIR/$folder"
}

subdomain_scan() {
    create_folder "Subdomains"
    log "Running Subdomain Enumeration..."
    amass enum -d "$target" -o "$BASE_DIR/Subdomains/amass.txt"
    sublist3r -d "$target" -o "$BASE_DIR/Subdomains/sublist3r.txt"
}

dns_scan() {
    create_folder "DNS"
    log "Running DNS Recon..."
    dnsrecon -d "$target" -t std > "$BASE_DIR/DNS/dnsrecon.txt"
}

web_scan() {
    create_folder "WebTech"
    log "Running Web Technology Scan..."
    whatweb "$target" > "$BASE_DIR/WebTech/whatweb.txt"
    wafw00f "$target" > "$BASE_DIR/WebTech/wafw00f.txt"
}

nmap_scan() {
    create_folder "Nmap"
    log "Running Nmap Scan..."
    nmap -A -T4 "$target" -oN "$BASE_DIR/Nmap/nmap.txt"
}

ssl_scan() {
    create_folder "SSL"
    log "Running SSL Scan..."
    sslscan "$target" > "$BASE_DIR/SSL/sslscan.txt"
}

cms_detection() {
    create_folder "CMS"
    log "Detecting CMS..."
    cmseek -u "$target" --follow-redirect > "$BASE_DIR/CMS/cmseek.txt"
}

osint_scan() {
    create_folder "OSINT"
    log "Running OSINT Harvesting..."
    theHarvester -d "$target" -b all > "$BASE_DIR/OSINT/theHarvester.txt"
}

directory_brute_force() {
    create_folder "BruteForce"
    log "Running Directory Brute Force..."
    gobuster dir -u "http://$target" -w /usr/share/wordlists/dirb/common.txt -o "$BASE_DIR/BruteForce/gobuster.txt"
}

generate_report() {
    log "Generating HTML Report..."
    report_file="$BASE_DIR/Report.html"
    echo "<html><head><title>OM Recon Report</title><style>body{font-family:Arial;} pre{background:#222;color:#fff;padding:10px;}</style></head><body>" > "$report_file"
    echo "<h1>OM Recon Report - $target</h1>" >> "$report_file"

    for dir in "$BASE_DIR"/*/; do
        folder=$(basename "$dir")
        for file in "$dir"/*.txt; do
            [[ -f "$file" ]] && echo "<h2>$folder - $(basename "$file")</h2><pre>$(cat "$file")</pre>" >> "$report_file"
        done
    done

    echo "</body></html>" >> "$report_file"
    log "Report generated at: $report_file"
}

# Auto-archive Function
archive_results() {
    zip -r "${BASE_DIR}.zip" "$BASE_DIR" >/dev/null 2>&1
    log "All results archived into: ${BASE_DIR}.zip"
}

# Interactive Menu
while true; do
    echo ""
    echo -e "${CYAN}Select an option:${RESET}"
    echo "1) Subdomain Enumeration"
    echo "2) DNS Recon"
    echo "3) Web Technology Scan"
    echo "4) Nmap Scan"
    echo "5) SSL Scan"
    echo "6) CMS Detection"
    echo "7) OSINT Harvesting"
    echo "8) Directory Brute Force"
    echo "9) Generate HTML Report"
    echo "10) Run All"
    echo "11) Exit"
    read -p "Enter choice: " choice

    case "$choice" in
        1) subdomain_scan ;;
        2) dns_scan ;;
        3) web_scan ;;
        4) nmap_scan ;;
        5) ssl_scan ;;
        6) cms_detection ;;
        7) osint_scan ;;
        8) directory_brute_force ;;
        9) generate_report ;;
        10) subdomain_scan; dns_scan; web_scan; nmap_scan; ssl_scan; cms_detection; osint_scan; directory_brute_force; generate_report; archive_results ;;
        11) log "Exiting..."; exit ;;
        *) echo -e "${RED}[ERROR] Invalid choice. Try again.${RESET}" ;;
    esac
done
