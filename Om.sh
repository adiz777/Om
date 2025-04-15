#!/bin/bash

# OM - Automated Reconnaissance Tool
# Author: Major_ADI
# Usage: ./om_recon.sh

# Color Codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Display Banner
echo -e "${CYAN}"
echo " ██████╗ ███╗   ███╗  "
echo "██╔═══██╗████╗ ████║ "
echo "██║   ██║██╔████╔██║ "
echo "██║   ██║██║╚██╔╝██║ "
echo "╚██████╔╝██║ ╚═╝ ██║ "
echo " ╚═════╝ ╚═╝     ╚═╝ "
echo -e "${RESET}"
echo -e "${GREEN}Welcome to OM - Automated Reconnaissance Tool${RESET}\n"

# Check and Install Required Tools
check_tools() {
    for tool in nmap amass whatweb dnsrecon sublist3r theHarvester gobuster sslscan wafw00f cmseek; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[ERROR] $tool is not installed. Installing it...${RESET}"
            # Try installing tools using apt, pip, or other installation methods
            if sudo apt install -y $tool; then
                echo -e "${GREEN}[INFO] $tool installed successfully.${RESET}"
            elif pip install $tool; then
                echo -e "${GREEN}[INFO] $tool installed successfully via pip.${RESET}"
            else
                echo -e "${RED}[ERROR] Failed to install $tool. Please install it manually.${RESET}"
                exit 1
            fi
        fi
    done
}
check_tools

# Input Target
target=""
while [[ -z "$target" ]]; do
    read -p "Enter the target domain (e.g., example.com): " target
    [[ -z "$target" ]] && echo -e "${RED}[ERROR] No target provided. Try again.${RESET}"
done

# Output Directory
OUTPUT_DIR="OM_Recon_$target"
LOG_FILE="$OUTPUT_DIR/recon_log.txt"
mkdir -p "$OUTPUT_DIR"

# Logging Function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}
log "Starting reconnaissance on $target"

# Reconnaissance Functions
subdomain_scan() {
    log "Running Subdomain Enumeration..."
    amass enum -d "$target" -o "$OUTPUT_DIR/subdomains.txt"
    sublist3r -d "$target" -o "$OUTPUT_DIR/sublist3r_subdomains.txt"
    log "Subdomain Enumeration completed."
}

dns_scan() {
    log "Running DNS Recon..."
    dnsrecon -d "$target" -t std > "$OUTPUT_DIR/dnsrecon.txt"
    log "DNS Recon completed."
}

web_scan() {
    log "Running Web Technology Scan..."
    whatweb "$target" > "$OUTPUT_DIR/webscan.txt"
    wafw00f "$target" > "$OUTPUT_DIR/wafw00f_results.txt"
    log "Web Technology Scan completed."
}

nmap_scan() {
    log "Running Nmap Scan..."
    nmap -A -T4 "$target" -oN "$OUTPUT_DIR/nmap_scan.txt"
    log "Nmap Scan completed."
}

ssl_scan() {
    log "Running SSL Scan..."
    sslscan "$target" > "$OUTPUT_DIR/sslscan.txt"
    log "SSL Scan completed."
}

cms_detection() {
    log "Detecting CMS..."
    cmseek -u "$target" --follow-redirect > "$OUTPUT_DIR/cms_detection.txt"
    log "CMS Detection completed."
}

open_ports() {
    log "Extracting Open Ports..."
    grep "open" "$OUTPUT_DIR/nmap_scan.txt" | awk '{print $1 " "$2 " "$3}' > "$OUTPUT_DIR/open_ports.txt"
    log "Open Ports extraction completed."
}

osint_scan() {
    log "Running OSINT Harvesting..."
    theHarvester -d "$target" -b all > "$OUTPUT_DIR/theHarvester_results.txt"
    log "OSINT Harvesting completed."
}

directory_brute_force() {
    log "Running Directory Brute Force Attack..."
    gobuster dir -u "http://$target" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/gobuster_results.txt"
    log "Directory Brute Force completed."
}

generate_report() {
    log "Generating HTML Report..."
    REPORT_FILE="$OUTPUT_DIR/report.html"
    echo "<html><head><title>OM Recon Report</title><style>body{font-family:Arial;} pre{background:#222;color:#fff;padding:10px;}</style></head><body>" > "$REPORT_FILE"
    echo "<h1>OM Recon Report - $target</h1>" >> "$REPORT_FILE"
    for file in subdomains.txt sublist3r_subdomains.txt dnsrecon.txt webscan.txt wafw00f_results.txt nmap_scan.txt open_ports.txt sslscan.txt cms_detection.txt theHarvester_results.txt gobuster_results.txt; do
        if [[ -f "$OUTPUT_DIR/$file" ]]; then
            echo "<h2>${file%.txt}</h2><pre>$(cat "$OUTPUT_DIR/$file")</pre>" >> "$REPORT_FILE"
        fi
    done
    echo "</body></html>" >> "$REPORT_FILE"
    log "Report saved: $REPORT_FILE"
}

# Interactive Menu
while true; do
    echo ""
    echo -e "${CYAN}Select an option:${RESET}"
    echo -e "1️⃣ Subdomain Enumeration"
    echo -e "2️⃣ DNS Recon"
    echo -e "3️⃣ Web Tech Scan"
    echo -e "4️⃣ Nmap Scan"
    echo -e "5️⃣ SSL Scan"
    echo -e "6️⃣ CMS Detection"
    echo -e "7️⃣ Open Ports Summary"
    echo -e "8️⃣ OSINT Harvesting"
    echo -e "9️⃣ Directory Brute Force"
    echo -e "🔟 Generate HTML Report"
    echo -e "1️⃣1️⃣ Run All"
    echo -e "1️⃣2️⃣ Exit"
    read -p "Enter choice: " choice
    case "$choice" in
        1) subdomain_scan ;;
        2) dns_scan ;;
        3) web_scan ;;
        4) nmap_scan ;;
        5) ssl_scan ;;
        6) cms_detection ;;
        7) open_ports ;;
        8) osint_scan ;;
        9) directory_brute_force ;;
        10) generate_report ;;
        11) subdomain_scan; dns_scan; web_scan; nmap_scan; ssl_scan; cms_detection; open_ports; osint_scan; directory_brute_force; generate_report ;;
        12) log "Exiting..."; exit ;;
        *) echo -e "${RED}Invalid option! Try again.${RESET}" ;;
    esac
done
