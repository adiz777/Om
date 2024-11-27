#!/bin/bash

# Tool Name: OM
# Description: A comprehensive reconnaissance tool for Kali Linux with reporting options.
# Created by Adiz777 (Enhanced by Gemini Advanced)

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
      sudo bash "$0" "<span class="math-inline">target"  \# Pass the target argument
exit
else
echo \-e "\\e\[1;33mSome tools might have limited functionality without root access\.\\e\[0m"
fi
fi
\}
function update\_system\(\) \{
echo \-e "\\e\[1;34mUpdating system\.\.\.\\e\[0m"
apt update \-y &\> /dev/null && apt upgrade \-y &\> /dev/null
\}
function check\_tools\(\) \{
tools\=\(nmap masscan sublist3r assetfinder amass dnsrecon dig host fierce whatweb nikto dirb gobuster wpscan theharvester enum4linux feroxbuster nuclei wkhtmltopdf\)
for tool in "</span>{tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
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
  mkdir -p "<span class="math-inline">output\_dir"
for tool in "</span>{tools[@]}"; do
    mkdir -p "$output_dir/$tool/$target"
  done
}

function get_recon_level() {
  local default_level="high"
  read -p "Enter desired reconnaissance level (low, medium, high) [default: <span class="math-inline">default\_level\]\: " level
level\=</span>{level:-$default_level}
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
  dnsrecon $dnsrecon_options -o "$output_dir/dnsrecon/$target/dnsrecon_scan.xml" -j "$output_dir/dnsrecon/$target/dnsrecon_scan.json" &  # Add JSON output
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
  fierce $fierce_options > "$output_dir/fierce/$target/fierce_scan.txt" 2>&1 &  # Redirect stderr to stdout
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
  nuclei -u "$target" -o "$output_dir/nuclei/<span class="math-inline">target/nuclei\_scan\.txt" &
echo "Nuclei scan is running in the background\.\.\."
\}
function generate\_report\(\) \{
echo \-e "\\e\[1;34mGenerating report\.\.\.\\e\[0m"
read \-p "Enter desired report format \(pdf, html, txt\) \[default\: txt\]\: " report\_format
report\_format\=</span>{report_format:-txt}

  # Ask for dark/light mode preference for HTML and PDF
  if [[ "$report_format" == "html" || "<span class="math-inline">report\_format" \=\= "pdf" \]\]; then
read \-p "Choose mode \(dark/light\) \[default\: dark\]\: " mode\_pref
mode\_pref\=</span>{mode_pref:-dark}
  fi

  case <span class="math-inline">report\_format in
pdf\)
echo "Generating PDF report\.\.\."
\# Create a temporary HTML file with the report content
tmp\_html\=</span>(mktemp)
      echo "<html><head><title>Reconnaissance Report - $target</title>" > "$tmp_html"

      # Apply dark/light mode styles based on user preference
      if [[ "$mode_pref" == "dark" ]]; then
        echo "<style>
          body { background-color: #222; color: #eee; font-family: sans-serif; }
          h1, h2 { color: #0f0; }
        </style></head><body>" >> "$tmp_html"
      else
        echo "<style>
          body { background-color: #eee; color: #222; font-family: sans-serif; }
          h1, h2 { color: #007bff; }
        </style></head><body>" >> "$tmp_html"
      fi

      echo "<h1>Reconnaissance Report - $target</h1>" >> "<span class="math-inline">tmp\_html"
for tool in "</span>{tools[@]}"; do
        echo "<h2>$tool</h2>" >> "$tmp_html"
        if [[ -f "$output_dir/$tool/$target/"*.txt ]]; then
          # Format tool output for PDF (e.g., using pre tags for code blocks)
          cat "$output_dir/$tool/<span class="math-inline">target/"\*\.txt \| sed 's/</span>/<br>/' >> "$tmp_html"
        else
          echo "<p>No output found for $tool.</p>" >> "$tmp_html"
        fi
      done

      echo "</body></html>" >> "$tmp_html"

      # Convert the temporary HTML to PDF using wkhtmltopdf
      wkhtmltopdf --quiet "$tmp_html" "$output_dir/$target/report.pdf"
      rm "$tmp_html"
      ;;

    html)
      # Generate HTML report with dark/light mode toggle and futuristic minimal styling
      echo "<html><head><title>Reconnaissance Report - $target</title>" > "$output_dir/$target/report.html"
      echo "<style>
        body { font-family: 'Roboto Mono', monospace; transition: background-color 0.3s ease, color 0.3s ease; }
        body.dark-mode { background-color: #222; color: #eee; }
        body.light-mode { background-color: #eee; color: #222; }
        h1, h2 { font-weight: bold; }
        h1 { font-size: 2.5em; margin-bottom: 0.5em; }
        h2 { font-size: 1.8em; margin-bottom: 0.3em; border-bottom: 2px solid; }
        table { width: 80%; margin: 20px auto; border-collapse: collapse; }
        th, td { border: 1px solid; padding: 8px; text-align: left; }
        .toggle-container {
          position: fixed; top: 10px; right: 10px;
          background-color: rgba(0, 0, 0, 0.7);
          border-radius: 5px; padding: 5px;
        }
        .toggle { appearance: none; -webkit-appearance: none; -moz-appearance: none;
          width: 40px; height: 20px; background: #ccc; border-radius: 10px;
          position: relative; cursor: pointer; outline: none; transition: background 0.3s ease;
        }
        .toggle:checked { background: #0f0; }
        .toggle::before { content: '';
          display: block; width: 16px; height: 16px; border-radius: 50%;
          background: #fff; position: absolute; top: 2px; left: 2px;
          transition: left 0.3s ease;
        }
        .toggle:checked::before { left: 22px; }
        pre { white-space: pre-wrap; } /* Preserve line breaks in preformatted text */
      </style></head><body class='$mode_pref-mode'>" >> "$output_dir/$target/report.html"

      # Dark/light mode toggle
      echo "<div class='toggle-container'>
              <input type='checkbox' id='mode-toggle' class='toggle'>
            </div>" >> "$output_dir/$target/report.html"

      echo "<script>
        const toggle = document.getElementById('mode-toggle');
        const body = document.body;
        toggle.addEventListener('change', () => {
          body.classList.toggle('dark-mode');
          body.classList.toggle('light-mode');
        });
      </script>" >> "$output_dir/$target/report.html"

      echo "<h1>Reconnaissance Report - $target</h1>" >> "$output_dir/<span class="math-inline">target/report\.html"
for tool in "</span>{tools[@]}"; do
        echo "<h2>$tool</h2>" >> "$output_dir/$target/report.html"
        if [[ -f "$output_dir/$tool/$target/"*.txt ]] || [[ -f "$output_dir/$tool/$target/"*.json ]]; then
          echo "<pre>" >> "$output_dir/$target/report.html"  # Wrap output in <pre> tags
          if [[ -f "$output_dir/$tool/$target/"*.txt ]]; then
            cat "$output_dir/$tool/$target/"*.txt >> "$output_dir/$target/report.html"
