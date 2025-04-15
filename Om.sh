#!/bin/bash

# OM - Automated Reconnaissance Tool v1
# Author: Major_ADI
# Usage: ./om_recon.sh

# Color Codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Spinner Animation
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\\'
    while [ -d /proc/$pid ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%$temp}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

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

# Check Required Tools
check_tools() {
    for tool in nmap amass whatweb dnsrecon sublist3r theHarvester gobuster sslscan waybackurls wafw00f cmseek gowitness; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[ERROR] $tool is not installed.${RESET}"
            echo -e "${YELLOW}Please install it manually using apt/pip/GitHub.${RESET}"
            exit 1
        fi
    done

    if [[ ! -f /usr/share/wordlists/dirb/common.txt ]]; then
        echo -e "${RED}[ERROR] Wordlist /usr/share/wordlists/dirb/common.txt not found.${RESET}"
        echo -e "${YELLOW}Please install 'dirb' or provide your own wordlist path.${RESET}"
        exit 1
    fi
}

read -p "Run full tool check? (y/n): " run_check
[[ "$run_check" =~ ^[Yy]$ ]] && check_tools

# Input Target
target=""
while [[ -z "$target" ]]; do
    read -p "Enter the target domain (e.g., example.com): " target
    if [[ ! "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[ERROR] Invalid domain format. Try again.${RESET}"
        target=""
    fi
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
    (amass enum -d "$target" -o "$OUTPUT_DIR/subdomains.txt" &
     sublist3r -d "$target" -o "$OUTPUT_DIR/sublist3r_subdomains.txt") & spinner
    log "Subdomain Enumeration completed."
}

dns_scan() {
    log "Running DNS Recon..."
    (dnsrecon -d "$target" -t std > "$OUTPUT_DIR/dnsrecon.txt") & spinner
    log "DNS Recon completed."
}

web_scan() {
    log "Running Web Technology Scan..."
    (whatweb "$target" > "$OUTPUT_DIR/webscan.txt"
     wafw00f "$target" > "$OUTPUT_DIR/wafw00f_results.txt") & spinner
    log "Web Technology Scan completed."
}

nmap_scan() {
    log "Running Nmap Scan..."
    (nmap -A -T4 "$target" -oN "$OUTPUT_DIR/nmap_scan.txt") & spinner
    log "Nmap Scan completed."
}

ssl_scan() {
    log "Running SSL Scan..."
    (sslscan "$target" > "$OUTPUT_DIR/sslscan.txt") & spinner
    log "SSL Scan completed."
}

wayback_scrape() {
    log "Fetching URLs from Wayback Machine..."
    (waybackurls "$target" > "$OUTPUT_DIR/waybackurls.txt") & spinner
    log "Wayback Machine Scraping completed."
}

cms_detection() {
    log "Detecting CMS..."
    (cmseek -u "$target" --follow-redirect > "$OUTPUT_DIR/cms_detection.txt") & spinner
    log "CMS Detection completed."
}

open_ports() {
    log "Extracting Open Ports..."
    grep "open" "$OUTPUT_DIR/nmap_scan.txt" | awk '{print $1 " "$2 " "$3}' > "$OUTPUT_DIR/open_ports.txt"
    log "Open Ports extraction completed."
}

osint_scan() {
    log "Running OSINT Harvesting..."
    (theHarvester -d "$target" -b all > "$OUTPUT_DIR/theHarvester_results.txt") & spinner
    log "OSINT Harvesting completed."
}

directory_brute_force() {
    log "Running Directory Brute Force Attack..."
    (gobuster dir -u "http://$target" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/gobuster_results.txt") & spinner
    log "Directory Brute Force completed."
}

screenshot_webapp() {
    log "Capturing Screenshot of Web App..."
    mkdir -p "$OUTPUT_DIR/screenshots"
    (gowitness single --url "http://$target" --destination "$OUTPUT_DIR/screenshots") & spinner
    log "Screenshot captured."
}

generate_report() {
    log "Generating HTML Report..."
    REPORT_FILE="$OUTPUT_DIR/report.html"
    echo "<html><head><title>OM Recon Report</title><style>body{font-family:Arial;background:#111;color:#eee;} pre{background:#222;padding:10px;} h1,h2{color:#00ffff;}</style></head><body>" > "$REPORT_FILE"
    echo "<h1>OM Recon Report - $target</h1>" >> "$REPORT_FILE"
    for file in *.txt; do
        [[ -f "$OUTPUT_DIR/$file" ]] && echo "<h2>${file%.txt}</h2><pre>$(cat "$OUTPUT_DIR/$file")</pre>" >> "$REPORT_FILE"
    done
    echo "<h2>Screenshots</h2><img src='screenshots/http_$target.png' width='600px'>" >> "$REPORT_FILE"
    echo "</body></html>" >> "$REPORT_FILE"
    log "Report saved: $REPORT_FILE"
}

threat_score() {
    log "Calculating Threat Score..."
    score=0
    grep -q "443/tcp open" "$OUTPUT_DIR/nmap_scan.txt" && score=$((score+1))
    grep -q "http" "$OUTPUT_DIR/webscan.txt" && score=$((score+2))
    grep -q "Apache" "$OUTPUT_DIR/webscan.txt" && score=$((score+1))
    grep -q "WordPress" "$OUTPUT_DIR/cms_detection.txt" && score=$((score+3))
    echo "Threat Score: $score / 10" | tee "$OUTPUT_DIR/threat_score.txt"
    log "Threat score evaluated."
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
    echo -e "6️⃣ Wayback Machine Scrape"
    echo -e "7️⃣ CMS Detection"
    echo -e "8️⃣ Open Ports Summary"
    echo -e "9️⃣ OSINT Harvesting"
    echo -e "🔟 Directory Brute Force"
    echo -e "1️⃣1️⃣ Capture Web Screenshot"
    echo -e "1️⃣2️⃣ Threat Score"
    echo -e "1️⃣3️⃣ Generate HTML Report"
    echo -e "1️⃣4️⃣ Run All"
    echo -e "1️⃣5️⃣ Exit"
    read -p "Enter choice: " choice
    case "$choice" in
        1) subdomain_scan ;;
        2) dns_scan ;;
        3) web_scan ;;
        4) nmap_scan ;;
        5) ssl_scan ;;
        6) wayback_scrape ;;
        7) cms_detection ;;
        8) open_ports ;;
        9) osint_scan ;;
        10) directory_brute_force ;;
        11) screenshot_webapp ;;
        12) threat_score ;;
        13) generate_report ;;
        14) subdomain_scan; dns_scan; web_scan; nmap_scan; ssl_scan; wayback_scrape; cms_detection; open_ports; osint_scan; directory_brute_force; screenshot_webapp; threat_score; generate_report ;;
        15) log "Exiting..."; exit ;;
        *) echo -e "${RED}Invalid option! Try again.${RESET}" ;;
    esac
done
