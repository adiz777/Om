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
  apt update -y &> /dev/null && apt upgrade -y &> /dev/null &
}

function check_tools() {
  tools=(nmap netdiscover zenmap masscan dnsrecon dig host fierce whatweb nikto dirb wpscan theharvester maltego recon-ng gobuster enum4linux)
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "\e[1;33m$tool not found. Installing in background...\e[0m"
      apt install -y "$tool" &> /dev/null &
    fi
  done
}

function get_target() {
  while [[ -z "$target" ]]; do
    read -p "Enter website or IP address: " target
    if [[ -z "$target" ]]; then
      echo -e "\e[1;31mNo input detected. Please provide a valid website or IP address.\e[0m"
    fi
  done
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
    low) nmap_options="-sT -sV" ;;
    medium) nmap_options="-A" ;;
    high) nmap_options="-A -p-" ;;
  esac
  nmap $nmap_options "$target" -oN "om_results/nmap/$target/nmap_scan.txt" &
  echo "nmap_$recon_level is running in the background..."

  # Netdiscover
  case $recon_level in
    low) netdiscover_options="-r $target/24 -P" ;;
    medium) netdiscover_options="-r $target/24" ;;
    high) netdiscover_options="-r $target/24 -p" ;;
  esac
  netdiscover $netdiscover_options -oN "om_results/netdiscover/$target/netdiscover_scan.txt" &
  echo "netdiscover_$recon_level is running in the background..."

  # Masscan
  case $recon_level in
    low) masscan_options="-p80,443" ;;
    medium) masscan_options="-p1-1000" ;;
    high) masscan_options="-p1-65535" ;;
  esac
  masscan $masscan_options "$target" -oG "om_results/masscan/$target/masscan_scan.txt" &
  echo "masscan_$recon_level is running in the background..."

  # Dnsrecon
  case $recon_level in
    low) dnsrecon_options="-d $target" ;;
    medium) dnsrecon_options="-d $target -t std,srv,axfr" ;;
    high) dnsrecon_options="-d $target -t std,srv,axfr,mx,soa,ns" ;;
  esac
  dnsrecon $dnsrecon_options -o "om_results/dnsrecon/$target/dnsrecon_scan.xml" &
  echo "dnsrecon_$recon_level is running in the background..."

  # Dig
  dig "$target" ANY > "om_results/dig/$target/dig_scan.txt" &
  echo "dig is running in the background..."

  # Host
  host -t ns "$target" > "om_results/host/$target/host_scan.txt" &
  echo "host is running in the background..."

  # Fierce
  case $recon_level in
    low) fierce_options="-dns $target" ;;
    medium) fierce_options="-dns $target -wide" ;;
    high) fierce_options="-dns $target -wide -connect" ;;
  esac
  fierce $fierce_options > "om_results/fierce/$target/fierce_scan.txt" &
  echo "fierce_$recon_level is running in the background..."

  # WhatWeb
  whatweb "$target" > "om_results/whatweb/$target/whatweb_scan.txt" &
  echo "whatweb is running in the background..."

  # Nikto
  case $recon_level in
    low) nikto_options="-h $target" ;;
    medium) nikto_options="-h $target -evasion 1" ;;
    high) nikto_options="-h $target -evasion 4" ;;
  esac
  nikto $nikto_options -o "om_results/nikto/$target/nikto_scan.txt" &
  echo "nikto_$recon_level is running in the background..."

  # Dirb
  dirb http://"$target" /usr/share/wordlists/dirb/common.txt -o "om_results/dirb/$target/dirb_scan.txt" &
  echo "dirb is running in the background..."

  # Gobuster
  case $recon_level in
    low) gobuster_options="-u http://$target -w /usr/share/wordlists/dirb/common.txt" ;;
    medium) gobuster_options="-u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ;;
    high) gobuster_options="-u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html,txt,js" ;;
  esac
  gobuster dir $gobuster_options -o "om_results/gobuster/$target/gobuster_scan.txt" &
  echo "gobuster_$recon_level is running in the background..."

  # WPScan
  case $recon_level in
    low) wpscan_options="--url $target" ;;
    medium) wpscan_options="--url $target --enumerate u" ;;
    high) wpscan_options="--url $target --enumerate u,p,t" ;;
  esac
  wpscan $wpscan_options -o "om_results/wpscan/$target/wpscan_scan.json" &
  echo "wpscan_$recon_level is running in the background..."

  # TheHarvester
  case $recon_level in
    low) theharvester_options="-d $target -l 100 -b all" ;;
    medium) theharvester_options="-d $target -l 500 -b all" ;;
    high) theharvester_options="-d $target -l 1000 -b all" ;;
  esac
  theharvester $theharvester_options > "om_results/theharvester/$target/theharvester_scan.txt" &
  echo "theharvester_$recon_level is running in the background..."
}

# Main Script Execution
banner
check_root
update_system
check_tools
get_target
create_directories
run_scans
