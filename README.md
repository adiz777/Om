# Om - Automated Reconnaissance Tool

## Description:
Om is a comprehensive reconnaissance tool designed for Kali Linux and other Linux distributions. It automates various command-line reconnaissance tools, offering security professionals and enthusiasts an efficient and organized way to gather intelligence on targets.

## Features:
- **Automated Scans**: Executes multiple reconnaissance tools including Nmap, Amass, Sublist3r, WhatWeb, DNSRecon, WafW00f, SSLScan, Wayback Machine Scraping, theHarvester, Gobuster, and CMSeek.
- **Organized Results**: Stores results in structured directories for easy analysis.
- **HTML Report Generation**: Automatically compiles findings into a detailed HTML report.
- **OSINT Gathering**: Leverages theHarvester to gather public intelligence.
- **CMS Detection**: Identifies content management systems (CMS) used by target websites.
- **Subdomain Enumeration**: Uses Amass and Sublist3r for discovering subdomains.
- **Port Scanning & Enumeration**: Performs comprehensive Nmap scans and extracts open ports.
- **SSL Analysis**: Checks SSL configurations and security vulnerabilities.
- **Historical Data Extraction**: Fetches archived URLs from the Wayback Machine.
- **Directory Brute-Forcing**: Uses Gobuster to find hidden directories and files.

## Minimum Requirements:
- **Operating System**: Kali Linux or other Debian-based Linux distributions (e.g., Parrot OS, BlackArch, Ubuntu)
- **Shell**: Bash
- **Privileges**: Root privileges (recommended for full functionality)
- **Dependencies**: Install required tools using:  
  `sudo apt install nmap amass sublist3r whatweb dnsrecon wafw00f sslscan waybackurls theHarvester gobuster cmseek`

## Installation:
1. Clone the repository:
   ```sh
   git clone https://github.com/Adiz777/om.git
   ```
2. Navigate to the project folder:
   ```sh
   cd om
   ```
3. Make the script executable:
   ```sh
   chmod +x om_recon.sh
   ```

## Usage:
1. Run the tool:
   ```sh
   sudo ./om_recon.sh
   ```
2. Enter the target domain when prompted.
3. Select the desired reconnaissance option from the interactive menu.
4. View the generated reports inside the output directory.

## Disclaimer:
This tool is intended for **educational and ethical purposes only**. Use it responsibly and **only** on systems you have explicit permission to scan. Unauthorized scanning is illegal and unethical.

## Contributing:
Contributions are welcome! Feel free to open issues or submit pull requests.

## Future Updates:
- **Attack Mode**: A planned feature to automate the exploitation of discovered vulnerabilities.
- **Improved Reporting**: Enhancing the HTML report with better visualization and analytics.

**Created by:** MAJOR_ADI ❤️

