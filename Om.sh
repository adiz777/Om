#!/bin/bash

# Tool Name: OM
# Description: A minimalist reconnaissance tool for Kali Linux.
# Created by Adiz777

# --- Functions ---

function banner() {
  echo -e "\e[1;32m
                                           
     OOOOOOOOO                             
   OO:::::::::OO                           
 OO:::::::::::::OO                         
O:::::::OOO:::::::O                        
O::::::O   O::::::O   mmmmmmm    mmmmmmm   
O:::::O     O:::::O mm:::::::m  m:::::::mm 
O:::::O     O:::::Om::::::::::mm::::::::::m
O:::::O     O:::::Om::::::::::::::::::::::m
O:::::O     O:::::Om:::::mmm::::::mmm:::::m
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
      sudo bash "$0"
      exit
    else
      echo -e "\e[1;33mSome tools might have limited functionality without root access.\e[0m"
    fi
  fi
}

function update_system() {
  echo -e "\e[1;34mUpdating system...\e[0m"
  apt update -y && apt upgrade -y
}

function check_tools() {
  tools=(nmap netdiscover zenmap angryip masscan dnsrecon dig host fierce whatweb nikto dirb wpscan theharvester maltego recon-ng)
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "\e[1;33m$tool not found. Installing...\e[0m"
      apt install -y "$tool"
    fi
  done
}

function get_target() {
  read -p "Enter website or IP address: " target
}

function create_directories() {
  mkdir -p "om_results"
  for tool in "${tools[@]}"; do
    mkdir -p "om_results/$tool/$target"
  done
}

function get_recon_level() {
  local default_level="high"
  read -p "Enter desired reconnaissance level (low, medium, high) [default: $default_level]: " level
  level=${level:-$default_level} 
  echo "$level"
}

function run_scans() {
  echo -e "\e[1;34mRunning reconnaissance scans...\e[0m"
  recon_level=$(get_recon_level)

  # Nmap
  case $recon_level in
    low) nmap -sT -sV "$target" -oN "om_results/nmap/$target/nmap_scan.txt" ;;
    medium) nmap -A "$target" -oN "om_results/nmap/$target/nmap_scan.txt" ;;
    high) nmap -A -p- "$target" -oN "om_results/nmap/$target/nmap_scan.txt" ;; 
  esac
  echo "nmap_$recon_level is running..."

  # Netdiscover
  case $recon_level in
    low) netdiscover -r "$target"/24 -P -oN "om_results/netdiscover/$target/netdiscover_scan.txt" ;; 
    medium) netdiscover -r "$target"/24 -oN "om_results/netdiscover/$target/netdiscover_scan.txt" ;;
    high) netdiscover -r "$target"/24 -p -oN "om_results/netdiscover/$target/netdiscover_scan.txt" ;; 
  esac
  echo "netdiscover_$recon_level is running..."

  # Angry IP Scanner
  case $recon_level in
    low) angryip scanner --range "$target"/24 -o "om_results/angryip/$target/angryip_scan.txt" ;;
    medium) angryip scanner --range "$target"/24 -d 100 -o "om_results/angryip/$target/angryip_scan.txt" ;; 
    high) angryip scanner --range "$target"/24 -d 10 -o "om_results/angryip/$target/angryip_scan.txt" ;; 
  esac
  echo "angryip_$recon_level is running..."

  # Masscan
  case $recon_level in
    low) masscan -p80,443 "$target" -oG "om_results/masscan/$target/masscan_scan.txt" ;;
    medium) masscan -p1-1000 "$target" -oG "om_results/masscan/$target/masscan_scan.txt" ;; 
    high) masscan -p1-65535 "$target" -oG "om_results/masscan/$target/masscan_scan.txt" ;; 
  esac
  echo "masscan_$recon_level is running..."

  # Dnsrecon
  case $recon_level in
    low) dnsrecon -d "$target" -o "om_results/dnsrecon/$target/dnsrecon_scan.xml" ;;
    medium) dnsrecon -d "$target" -t std,srv,axfr -o "om_results/dnsrecon/$target/dnsrecon_scan.xml" ;; 
    high) dnsrecon -d "$target" -t std,srv,axfr,mx,soa,ns -o "om_results/dnsrecon/$target/dnsrecon_scan.xml" ;; 
  esac
  echo "dnsrecon_$recon_level is running..."

  # Dig
  dig "$target" ANY > "om_results/dig/$target/dig_scan.txt" 
  echo "dig is running..."

  # Host
  host -t ns "$target" > "om_results/host/$target/host_scan.txt"
  echo "host is running..."

  # Fierce
  case $recon_level in
    low) fierce -dns "$target" > "om_results/fierce/$target/fierce_scan.txt" ;;
    medium) fierce -dns "$target" -wide > "om_results/fierce/$target/fierce_scan.txt" ;; 
    high) fierce -dns "$target" -wide -connect > "om_results/fierce/$target/fierce_scan.txt" ;; 
  esac
  echo "fierce_$recon_level is running..."

  # WhatWeb
  whatweb "$target" > "om_results/whatweb/$target/whatweb_scan.txt"
  echo "whatweb is running..."

  # Nikto
  case $recon_level in
    low) nikto -h "$target" -o "om_results/nikto/$target/nikto_scan.txt" ;;
    medium) nikto -h "$target" -evasion 1 -o "om_results/nikto/$target/nikto_scan.txt" ;; 
    high) nikto -h "$target" -evasion 4 -o "om_results/nikto/$target/nikto_scan.txt" ;; 
  esac
  echo "nikto_$recon_level is running..."

  # Dirb
  dirb http://"$target" /usr/share/wordlists/dirb/common.txt -o "om_results/dirb/$target/dirb_scan.txt"
  echo "dirb is running..."

  # WPScan
  case $recon_level in
    low) wpscan --url "$target" -o "om_results/wpscan/$target/wpscan_scan.json" ;;
    medium) wpscan --url "$target" --enumerate u -o "om_results/wpscan/$target/wpscan_scan.json" ;; 
    high) wpscan --url "$target" --enumerate u,p,t -o "om_results/wpscan/$target/wpscan_scan.json" ;; 
  esac
  echo "wpscan_$recon_level is running..."

  # TheHarvester
  case $recon_level in
    low) theharvester -d "$target" -l 100 -b google > "om_results/theharvester/$target/theharvester_scan.txt" ;; 
    medium) theharvester -d "$target" -l 500 -b google > "om_results/theharvester/$target/theharvester_scan.txt" ;;
    high) theharvester -d "$target" -l 1000 -b google,bing,linkedin > "om_results/theharvester/$target/theharvester_scan.txt" ;;
  esac
  echo "theharvester_$recon_level is running..."
}

# --- Main Script Execution ---
banner
check_root
update_system
check_tools
get_target
create_directories
run_scans
