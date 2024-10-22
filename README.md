# OM - Automated Reconnaissance Tool

**Description:**

OM is a minimalist reconnaissance tool for Kali Linux and other Linux distributions designed to automate the execution of various command-line reconnaissance tools. It provides a streamlined approach to information gathering, helping security professionals and enthusiasts perform efficient and comprehensive reconnaissance.

**Features:**

* **Automated Scans:** Automates the execution of popular reconnaissance tools like Nmap, Netdiscover, Dnsrecon, WhatWeb, Nikto, and more.
* **Organized Results:**  Stores results in a structured directory hierarchy for easy access and analysis.
* **HTML Report:** Generates a basic HTML report summarizing the findings.
* **Minimalist Design:**  Focuses on a clean and efficient terminal interface.
* **Easy to Use:**  Simple execution with minimal user interaction.
* **Configurable Reconnaissance Levels:** Allows you to choose between low, medium, and high reconnaissance levels, adjusting the intensity of the scans.

**Minimum Requirements:**

* **Operating System:** Kali Linux or other Linux distributions (e.g., Parrot OS, BlackArch, Debian, Ubuntu)
* **Shell:** Bash
* **Privileges:** Root privileges (recommended for optimal functionality)
* **Connectivity:**  Internet connection

**Installation:**

1. Clone the repository: `git clone https://github.com/Adiz777/om.git`
2. Make the tool executable: `chmod +x om.sh`
3. Install the required tools: 

   *  Using apt: `sudo apt update && sudo apt install -y nmap netdiscover zenmap angryip masscan dnsrecon dig host fierce whatweb nikto dirb wpscan theharvester maltego recon-ng`

**Usage:**

1. Run the tool: `sudo ./om.sh` (or `./om.sh` if not using sudo)
2. Enter the target website or IP address when prompted.
3. Select the desired reconnaissance level (low, medium, or high).

**Disclaimer:**

This tool is intended for educational and ethical use only. Use it responsibly and only on systems you have permission to scan. Unauthorized scanning is illegal and unethical.

**Contributing:**

Contributions are welcome! Feel free to open issues or submit pull requests.

**Future Updates:**

* **Attack Mode:**  An attack mode is planned for future releases, allowing for automated exploitation of discovered vulnerabilities.

**Created by MAJOR_ADI ❤️**
