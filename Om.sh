#!/bin/bash

# Tool Name: OM
# Description: A comprehensive reconnaissance tool for Kali Linux with HTML reporting.
# Created by Adityarajsinh Zala

# --- Configuration ---

# Output directory
output_dir="om_results"

# Wordlists
common_wordlist="/usr/share/wordlists/dirb/common.txt"
medium_wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
small_wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

# --- Functions ---

function banner() {
    echo -e "\e[1;32m
                        
     OOOOOOOOO                     
 OO:::::::::OO                     
OO:::::::::::::OO                    
O:::::::OOO:::::::O                  
O::::::O   O::::::O   mmmmmmm   mmmmmmm  
O:::::O     O:::::O mm:::::::m m:::::::mm 
O:::::O     O:::::Om::::::::::mm::::::::::m
O:::::O     O:::::Om::::::::::::::::::::::m
O:::::O     O:::::Om:::::mmm::::::mmm:::::m
O:::::O     O:::::Om::::m   m::::m   m::::m
O:::::O     O:::::Om::::m   m::::m   m::::m
O:::::O     O:::::Om::::m   m::::m   m::::m
O:::::O     O:::::Om::::m   m::::m   m::::m
O:::::O     O:::::Om::::m   m::::m   m::::m
O::::::O   O::::::Om::::m   m::::m   m::::m
O:::::::OOO:::::::Om::::m   m::::m   m::::m
 OO:::::::::::::OO  m::::m   m::::m   m::::m
  OO:::::::::OO   m::::m   m::::m   m::::m
    OOOOOOOOO     mmmmmm   mmmmmm   mmmmmm
                        
                        
\e[0m"
}

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "\e[1;31mThis tool requires root privileges for optimal functionality.\e[0m"
        read -p "Do you want to run it with sudo? (y/n) " choice
        if [[ $choice == "y" || $choice == "Y" ]]; then
            sudo bash "$0" "$target"  # Pass the target argument
            exit
        else
            echo -e "\e[1;33mSome tools might have limited functionality without root access.\e[0m"
        fi
    fi
}

function update_system() {
    echo -e "\e[1;34mUpdating system...\e[0m"
    apt update -y &> /dev/null && apt upgrade -y &> /dev/null
}

function check_tools() {
    tools=(nmap masscan sublist3r assetfinder amass dnsrecon dig host fierce whatweb nikto dirb gobuster wpscan theharvester enum4linux feroxbuster nuclei)
    for tool in "${tools[@]}"; do
        if! command -v "$tool" &> /dev/null; then
            echo -e "\e[1;33m$tool not found. Installing...\e[0m"
            apt install -y "$tool" &> /dev/null
            if [[ $? -ne 0 ]]; then
                echo -e "\e[1;31mError installing $tool. Please install it manually.\e[0m"
            fi
        fi
    done
}

function get_target() {
    if [[ -n "$1" ]]; then
        target="$1"
    else
        while [[ -z "$target" ]]; do
            read -p "Enter website or IP address: " target
            if [[ -z "$target" ]]; then
                echo -e "\e[1;31mNo input detected. Please provide a valid website or IP address.\e[0m"
            fi
        done
    fi
}

function create_directories() {
    mkdir -p "$output_dir/$target"
    for tool in "${tools[@]}"; do
        mkdir -p "$output_dir/$target/$tool"
    done
}

function get_recon_level() {
    local default_level="high"
    read -p "Enter desired reconnaissance level (low, medium, high) [default: $default_level]: " level
    level=${level:-$default_level}
    echo "$level"
}

function initialize_html_report() {
    local report_file="$output_dir/$target/om_report.html"
    echo "<html><head><title>OM Reconnaissance Report - $target</title></head><body>" > "$report_file"
    echo "<h1>OM Reconnaissance Report</h1>" >> "$report_file"
    echo "<h2>Target: $target</h2>" >> "$report_file"
    echo "<h3>Reconnaissance Level: $recon_level</h3>" >> "$report_file"
    echo "<hr>" >> "$report_file"
}

function add_to_html_report() {
    local tool_name="$1"
    local output_file="$2"
    echo "<h2>$tool_name</h2>" >> "$output_dir/$target/om_report.html"
    echo "<pre>" >> "$output_dir/$target/om_report.html"
    cat "$output_file" >> "$output_dir/$target/om_report.html"
    echo "</pre><hr>" >> "$output_dir/$target/om_report.html"
}

function finalize_html_report() {
    echo "</body></html>" >> "$output_dir/$target/om_report.html"
    echo -e "\e[1;32m[+] HTML report generated: $output_dir/$target/om_report.html\e[0m"
}

function run_subdomain_enumeration() {
    echo -e "\e[1;34mEnumerating subdomains...\e[0m"
    sublist3r -d "$target" -o "$output_dir/$target/sublist3r/subdomains.txt" &
    assetfinder --subs-only "$target" > "$output_dir/$target/assetfinder/subdomains.txt" &
    amass enum -d "$target" -o "$output_dir/$target/amass/subdomains.txt" &
    wait  # Wait for all subdomain enumeration tools to finish
    echo "Subdomain enumeration completed."
    add_to_html_report "Sublist3r" "$output_dir/$target/sublist3r/subdomains.txt"
    add_to_html_report "Assetfinder" "$output_dir/$target/assetfinder/subdomains.txt"
    add_to_html_report "Amass" "$output_dir/$target/amass/subdomains.txt"
}

function run_nmap_scan() {
    echo -e "\e[1;34mRunning Nmap scan...\e[0m"
    case $recon_level in
        low) nmap_options="-sT -sV";;
        medium) nmap_options="-A";;
        high) nmap_options="-A -p-";;
    esac
    nmap $nmap_options "$target" -oN "$output_dir/$target/nmap/nmap_scan.txt"
    echo "Nmap scan completed."
    add_to_html_report "Nmap Scan" "$output_dir/$target/nmap/nmap_scan.txt"
}

function run_masscan_scan() {
    echo -e "\e[1;34mRunning Masscan scan...\e[0m"
    case $recon_level in
        low) masscan_options="-p80,443";;
        medium) masscan_options="-p1-1000";;
        high) masscan_options="-p1-65535";;
    esac
    masscan $masscan_options "$target" -oG "$output_dir/$target/masscan/masscan_scan.txt"
    echo "Masscan scan completed."
    add_to_html_report "Masscan Scan" "$output_dir/$target/masscan/masscan_scan.txt"
}

function run_dns_enumeration() {
    echo -e "\e[1;34mRunning DNS enumeration...\e[0m"
    case $recon_level in
        low) dnsrecon_options="-d $target";;
        medium) dnsrecon_options="-d $target -t std,srv,axfr";;
        high) dnsrecon_options="-d $target -t std,srv,axfr,mx,soa,ns";;
    esac
    dnsrecon $dnsrecon_options -d $target -o "$output_dir/$target/dnsrecon/dnsrecon_scan.xml" -j "$output_dir/$target/dnsrecon/dnsrecon_scan.json"
    dig "$target" ANY > "$output_dir/$target/dig/dig_scan.txt"
    host -t ns "$target" > "$output_dir/$target/host/host_scan.txt"
    echo "DNS enumeration completed."
    add_to_html_report "DNSRecon" "$output_dir/$target/dnsrecon/dnsrecon_scan.xml"
    add_to_html_report "Dig" "$output_dir/$target/dig/dig_scan.txt"
    add_to_html_report "Host" "$output_dir/$target/host/host_scan.txt"
}

function run_fierce_scan() {
    echo -e "\e[1;34mRunning Fierce scan...\e[0m"
    case $recon_level in
        low) fierce_options="-dns $target";;
        medium) fierce_options="-dns $target -wide";;
        high) fierce_options="-dns $target -wide -connect";;
    esac
    fierce $fierce_options > "$output_dir/$target/fierce/fierce_scan.txt" 2>&1
    echo "Fierce scan completed."
    add_to_html_report "Fierce Scan" "$output_dir/$target/fierce/fierce_scan.txt"
}

function run_web_server_analysis() {
    echo -e "\e[1;34mRunning web server analysis...\e[0m"
    whatweb "$target" > "$output_dir/$target/whatweb/whatweb_scan.txt"

    case $recon_level in
        low) nikto_options="-h $target";;
        medium) nikto_options="-h $target -evasion 1";;
        high) nikto_options="-h $target -evasion 4";;
    esac
    nikto $nikto_options -o "$output_dir/$target/nikto/nikto_scan.txt"
    echo "Web server analysis completed."
    add_to_html_report "WhatWeb" "$output_dir/$target/whatweb/whatweb_scan.txt"
    add_to_html_report "Nikto" "$output_dir/$target/nikto/nikto_scan.txt"
}

function run_directory_bruteforcing() {
    echo -e "\e[1;34mRunning directory bruteforcing...\e[0m"
    case $recon_level in
        low)
            gobuster_options="-u http://$target -w $common_wordlist"
            feroxbuster_options="-u http://$target -w $common_wordlist"
          ;;
        medium)
            gobuster_options="-u http://$target -w $medium_wordlist"
            feroxbuster_options="-u http://$target -w $medium_wordlist"
          ;;
        high)
            gobuster_options="-u http://$target -w $small_wordlist -x php,html,txt,js"
            feroxbuster_options="-u http://$target -w $small_wordlist -x php,html,txt,js"
          ;;
    esac
    gobuster dir $gobuster_options -o "$output_dir/$target/gobuster/gobuster_scan.txt"
    feroxbuster $feroxbuster_options -o "$output_dir/$target/feroxbuster/feroxbuster_scan.txt"
    echo "Directory bruteforcing completed."
    add_to_html_report "Gobuster" "$output_dir/$target/gobuster/gobuster_scan.txt"
    add_to_html_report "Feroxbuster" "$output_dir/$target/feroxbuster/feroxbuster_scan.txt"
}

function run_wpscan() {
    echo -e "\e[1;34mRunning WPScan...\e[0m"
    case $recon_level in
        low) wpscan_options="--url $target";;
        medium) wpscan_options="--url $target --enumerate u";;
        high) wpscan_options="--url $target --enumerate u,p,t";;
    esac
    wpscan $wpscan_options -o "$output_dir/$target/wpscan/wpscan_scan.json"
    echo "WPScan completed."
    add_to_html_report "WPScan" "$output_dir/$target/wpscan/wpscan_scan.json"
}

function run_theharvester() {
    echo -e "\e[1;34mRunning TheHarvester...\e[0m"
    case $recon_level in
        low) theharvester_options="-d $target -l 100 -b all";;
        medium) theharvester_options="-d $target -l 500 -b all";;
        high) theharvester_options="-d $target -l 1000 -b all";;
    esac
    theharvester $theharvester_options > "$output_dir/$target/theharvester/theharvester_scan.txt"
    echo "TheHarvester completed."
    add_to_html_report "TheHarvester" "$output_dir/$target/theharvester/theharvester_scan.txt"
}

function run_vulnerability_scanning() {
    echo -e "\e[1;34mRunning vulnerability scanning...\e[0m"
    nuclei -u "$target" -o "$output_dir/$target/nuclei/nuclei_scan.txt"
    echo "Nuclei scan completed."
    add_to_html_report "Nuclei" "$output_dir/$target/nuclei/nuclei_scan.txt"
}

# --- Main Script Execution ---

clear

banner
check_root
update_system
check_tools
get_target "$@"

create_directories  # Create directories before getting recon level
recon_level=$(get_recon_level)
initialize_html_report  # Initialize HTML report

run_subdomain_enumeration
run_nmap_scan
run_masscan_scan
run_dns_enumeration
run_fierce_scan
run_web_server_analysis
run_directory_bruteforcing
run_wpscan
run_theharvester
run_vulnerability_scanning

finalize_html_report  # Finalize the HTML report
