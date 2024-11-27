#!/bin/bash

# Tool Name: OM
# Description: A comprehensive reconnaissance tool for Kali Linux with reporting options.
# Created by Adiz777 (Enhanced by Gemini Advanced)

# --- Configuration ---
# (You can customize these settings)

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
O::::::O   O::::::Om::::m   m::::m   m::::m
O:::::::OOO:::::::Om::::m   m::::m   m::::m
 OO:::::::::::::OO m::::m   m::::m   m::::m
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
  apt update -y &> /dev/null && apt upgrade -y &> /dev/null &
}

function check_tools() {
  tools=(nmap masscan sublist3r assetfinder amass dnsrecon dig host fierce whatweb nikto dirb gobuster wpscan theharvester enum4linux feroxbuster nuclei wkhtmltopdf)
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "\e[1;33m$tool not found. Installing in background...\e[0m"
      apt install -y "$tool" &> /dev/null &
    fi
  done
}

function get_target() {
  # Check if target is provided as an argument
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
  mkdir -p "$output_dir"
  for tool in "${tools[@]}"; do
    mkdir -p "$output_dir/$tool/$target"
  done
}

function get_recon_level() {
  local default_level="high"
  read -p "Enter desired reconnaissance level (low, medium, high) [default: $default_level]: " level
  level=${level:-$default_level}
  echo "$level"
}

function run_subdomain_enumeration() {
  echo -e "\e[1;34mEnumerating subdomains...\e[0m"
  sublist3r -d "$target" -o "$output_dir/sublist3r/$target/subdomains.txt" &
  assetfinder --subs-only "$target" > "$output_dir/assetfinder/$target/subdomains.txt" &
  amass enum -d "$target" -o "$output_dir/amass/$target/subdomains.txt" &
  echo "Subdomain enumeration is running in the background..."
}

function run_nmap_scan() {
  echo -e "\e[1;34mRunning Nmap scan...\e[0m"
  case $recon_level in
    low) nmap_options="-sT -sV" ;;
    medium) nmap_options="-A" ;;
    high) nmap_options="-A -p-" ;;
  esac
  nmap $nmap_options "$target" -oN "$output_dir/nmap/$target/nmap_scan.txt" &
  echo "Nmap scan is running in the background..."
}

function run_masscan_scan() {
  echo -e "\e[1;34mRunning Masscan scan...\e[0m"
  case $recon_level in
    low) masscan_options="-p80,443" ;;
    medium) masscan_options="-p1-1000" ;;
    high) masscan_options="-p1-65535" ;;
  esac
  masscan $masscan_options "$target" -oG "$output_dir/masscan/$target/masscan_scan.txt" &
  echo "Masscan scan is running in the background..."
}

function run_dns_enumeration() {
  echo -e "\e[1;34mRunning DNS enumeration...\e[0m"
  case $recon_level in
    low) dnsrecon_options="-d $target" ;;
    medium) dnsrecon_options="-d $target -t std,srv,axfr" ;;
    high) dnsrecon_options="-d $target -t std,srv,axfr,mx,soa,ns" ;;
  esac
  dnsrecon $dnsrecon_options -o "$output_dir/dnsrecon/$target/dnsrecon_scan.xml" &
  dig "$target" ANY > "$output_dir/dig/$target/dig_scan.txt" &
  host -t ns "$target" > "$output_dir/host/$target/host_scan.txt" &
  echo "DNS enumeration is running in the background..."
}

function run_fierce_scan() {
  echo -e "\e[1;34mRunning Fierce scan...\e[0m"
  case $recon_level in
    low) fierce_options="-dns $target" ;;
    medium) fierce_options="-dns $target -wide" ;;
    high) fierce_options="-dns $target -wide -connect" ;;
  esac
  fierce $fierce_options > "$output_dir/fierce/$target/fierce_scan.txt" &
  echo "Fierce scan is running in the background..."
}

function run_web_server_analysis() {
  echo -e "\e[1;34mRunning web server analysis...\e[0m"
  whatweb "$target" > "$output_dir/whatweb/$target/whatweb_scan.txt" &

  case $recon_level in
    low) nikto_options="-h $target" ;;
    medium) nikto_options="-h $target -evasion 1" ;;
    high) nikto_options="-h $target -evasion 4" ;;
  esac
  nikto $nikto_options -o "$output_dir/nikto/$target/nikto_scan.txt" &
  echo "Web server analysis is running in the background..."
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
  gobuster dir $gobuster_options -o "$output_dir/gobuster/$target/gobuster_scan.txt" &
  feroxbuster $feroxbuster_options -o "$output_dir/feroxbuster/$target/feroxbuster_scan.txt" &
  echo "Directory bruteforcing is running in the background..."
}

function run_wpscan() {
  echo -e "\e[1;34mRunning WPScan...\e[0m"
  case $recon_level in
    low) wpscan_options="--url $target" ;;
    medium) wpscan_options="--url $target --enumerate u" ;;
    high) wpscan_options="--url $target --enumerate u,p,t" ;;
  esac
  wpscan $wpscan_options -o "$output_dir/wpscan/$target/wpscan_scan.json" &
  echo "WPScan is running in the background..."
}

function run_theharvester() {
  echo -e "\e[1;34mRunning TheHarvester...\e[0m"
  case $recon_level in
    low) theharvester_options="-d $target -l 100 -b all" ;;
    medium) theharvester_options="-d $target -l 500 -b all" ;;
    high) theharvester_options="-d $target -l 1000 -b all" ;;
  esac
  theharvester $theharvester_options > "$output_dir/theharvester/$target/theharvester_scan.txt" &
  echo "TheHarvester is running in the background..."
}

function run_vulnerability_scanning() {
  echo -e "\e[1;34mRunning vulnerability scanning...\e[0m"
  nuclei -u "$target" -o "$output_dir/nuclei/$target/nuclei_scan.txt" &
  echo "Nuclei scan is running in the background..."
}

function generate_report() {
  echo -e "\e[1;34mGenerating report...\e[0m"

  read -p "Enter desired report format (pdf, html, txt) [default: txt]: " report_format
  report_format=${report_format:-txt}

  case $report_format in
    pdf)
      echo "Generating PDF report..."
      wkhtmltopdf --quiet "$output_dir/$target/"*.txt "$output_dir/$target/report.pdf"
      ;;

    html)
      # Generate an HTML report with dark mode and futuristic styling
      echo "<html><head><title>Reconnaissance Report - $target</title>" > "$output_dir/$target/report.html"
      echo "<style>
        body { background-color: #222; color: #eee; font-family: monospace; }
        h1, h2, h3 { color: #0f0; }
        table { width: 80%; margin: 20px auto; border-collapse: collapse; }
        th, td { border: 1px solid #555; padding: 10px; text-align: left; }
      </style></head><body>" >> "$output_dir/$target/report.html"
      echo "<h1>Reconnaissance Report - $target</h1>" >> "$output_dir/$target/report.html"

      for tool in "${tools[@]}"; do
        echo "<h2>$tool</h2>" >> "$output_dir/$target/report.html"
        if [[ -f "$output_dir/$tool/$target/"*.txt ]]; then
          echo "<table>" >> "$output_dir/$target/report.html"
          # Process the output of each tool and format it into an HTML table
          cat "$output_dir/$tool/$target/"*.txt | sed 's/$/<br>/' | while read line; do echo "<tr><td>$line</td></tr>"; done >> "$output_dir/$target/report.html"
          echo "</table>" >> "$output_dir/$target/report.html"
        else
          echo "<p>No output found for $tool.</p>" >> "$output_dir/$target/report.html"
        fi
      done

      echo "</body></html>" >> "$output_dir/$target/report.html"
      ;;

    txt)
      # Generate a simple, human-readable text report
      echo "Reconnaissance Report - $target" > "$output_dir/$target/report.txt"
      for tool in "${tools[@]}"; do
        if [[ -f "$output_dir/$tool/$target/"*.txt ]]; then  # Check if output files exist
          echo "\n$tool\n" >> "$output_dir/$target/report.txt"
          cat "$output_dir/$tool/$target/"* >> "$output_dir/$target/report.txt"
        fi
      done
      ;;

    *)
      echo "Invalid report format. Using default (txt)."
      generate_report  # Call the function again to use the default
      ;;
  esac
}

# --- Main Script Execution ---

banner
check_root
update_system
check_tools  # This will now install wkhtmltopdf if not found
get_target "$@"  # Pass all arguments to get_target
create_directories
recon_level=$(get_recon_level)

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

# Wait for background processes to finish
wait

generate_report