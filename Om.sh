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
echo " ██████╗ ███╗   ███╗ ";
echo "██╔═══██╗████╗ ████║ ";
echo "██║   ██║██╔████╔██║ ";
echo "██║   ██║██║╚██╔╝██║ ";
echo "╚██████╔╝██║ ╚═╝ ██║ ";
echo " ╚═════╝ ╚═╝     ╚═╝ ";
echo -e "${RESET}"
echo -e "${GREEN}Welcome to OM - Automated Reconnaissance Tool${RESET}"
echo ""

# Check Required Tools
check_tools() {
    for tool in nmap amass whatweb dnsrecon; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[ERROR] $tool is not installed. Install it using: sudo apt install $tool${RESET}"
            exit 1
        fi
    done
}

# Interactive Target Input
read -p "Enter the target domain (e.g., example.com): " TARGET
if [ -z "$TARGET" ]; then
    echo -e "${RED}[ERROR] No target provided. Exiting.${RESET}"
    exit 1
fi

# Create output and log directories
OUTPUT_DIR="OM_Recon_$TARGET"
LOG_FILE="$OUTPUT_DIR/recon_log.txt"
mkdir -p $OUTPUT_DIR

# Logging Function
log() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$TIMESTAMP] $1" | tee -a $LOG_FILE
}

log "Starting reconnaissance on $TARGET"

# Function for Subdomain Enumeration
subdomain_scan() {
    log "Starting Subdomain Enumeration..."
    amass enum -d $TARGET -o $OUTPUT_DIR/subdomains.txt
    log "Subdomain Enumeration completed. Results saved in subdomains.txt"
}

# Function for DNS Recon
dns_scan() {
    log "Starting DNS Reconnaissance..."
    dnsrecon -d $TARGET -t std > $OUTPUT_DIR/dnsrecon.txt
    log "DNS Recon completed. Results saved in dnsrecon.txt"
}

# Function for Web Technology Scan
web_scan() {
    log "Starting Web Technology Scan..."
    whatweb $TARGET > $OUTPUT_DIR/webscan.txt
    log "Web Tech Scan completed. Results saved in webscan.txt"
}

# Function for Nmap Scan
nmap_scan() {
    log "Starting Nmap Scan..."
    nmap -A -T4 $TARGET -oN $OUTPUT_DIR/nmap_scan.txt
    log "Nmap Scan completed. Results saved in nmap_scan.txt"
}

# Function for Open Ports Summary
open_ports() {
    log "Extracting Open Ports..."
    grep "open" $OUTPUT_DIR/nmap_scan.txt | awk '{print $1 " " $2 " " $3}' > $OUTPUT_DIR/open_ports.txt
    log "Open Ports extraction completed. Results saved in open_ports.txt"
}

# Function for Generating HTML Report
generate_report() {
    log "Generating HTML Report..."
    HTML_REPORT="$OUTPUT_DIR/report.html"
    echo "<html><head><title>OM Recon Report - $TARGET</title></head><body>" > $HTML_REPORT
    echo "<h1>OM Reconnaissance Report</h1>" >> $HTML_REPORT
    echo "<h2>Target: $TARGET</h2>" >> $HTML_REPORT

    for file in subdomains.txt dnsrecon.txt webscan.txt nmap_scan.txt open_ports.txt; do
        if [ -f "$OUTPUT_DIR/$file" ]; then
            echo "<h3>${file%.txt}</h3><pre>" >> $HTML_REPORT
            cat "$OUTPUT_DIR/$file" >> $HTML_REPORT
            echo "</pre>" >> $HTML_REPORT
        fi
    done

    echo "</body></html>" >> $HTML_REPORT
    log "Report generation completed. Report saved as report.html"
}

# Interactive Menu
while true; do
    echo ""
    echo -e "${CYAN}Choose an option:${RESET}"
    echo -e "1️⃣ Subdomain Enumeration"
    echo -e "2️⃣ DNS Reconnaissance"
    echo -e "3️⃣ Web Technology Scan"
    echo -e "4️⃣ Nmap Scan"
    echo -e "5️⃣ Open Ports Summary"
    echo -e "6️⃣ Generate HTML Report"
    echo -e "7️⃣ Run All Scans"
    echo -e "8️⃣ Exit"
    read -p "Enter your choice: " choice

    case $choice in
        1) subdomain_scan ;;
        2) dns_scan ;;
        3) web_scan ;;
        4) nmap_scan ;;
        5) open_ports ;;
        6) generate_report ;;
        7) 
            subdomain_scan
            dns_scan
            web_scan
            nmap_scan
            open_ports
            generate_report
            ;;
        8) log "Exiting script. Recon completed."; exit ;;
        *) echo -e "${RED}Invalid choice! Please select a valid option.${RESET}" ;;
    esac
done
