# Wireless Protocol Investigation Lab - Assignment 2
Group: Noa Bouchnick, Dael Hacohen Waingarten, Shir Bismuth
Course: Wireless and Mobile Network Security

## Project Overview
This repository contains the evidence, analysis scripts, and final report for the 802.11 
security investigation lab. The project explores client behavior, security parameter 
enforcement, and handshake transitions across different WPA2/WPA3 configurations.

## Hardware & Environment
- Access Point Adapter: Tenda N151 (USB ID: 002:c2e0a2)
- Monitoring Adapter: EDUP AX3000 WiFi 6 (USB ID: 006:ad5857)
- OS: DragonOS Noble
- Software: hostapd v2.10, Wireshark v4.4.2, dnsmasq

## Laboratory Setup
### 1. Access Point (Rogue AP) Deployment
To initialize the rogue access point for a specific experimental condition, use the 
following commands:

  # Set up IP address
  sudo ip addr add 192.168.10.1/24 dev wlxc83a35c2e0a2
  sudo ip link set wlxc83a35c2e0a2 up
  
  # Start DHCP/DNS service
  sudo dnsmasq -C dnsmasq2.conf
  
  # Launch AP with specific security configuration:
  sudo hostapd hostapd_lab_BASELINE.config
  # Alternatives: hostapd_lab_with_PMF.config, hostapd_lab_with_TKIP.config, hostapd_lab_with_WPA3.config

### 2. Traffic Monitoring
To capture traffic in monitor mode on Channel 6:

  # Prepare interface
  sudo airmon-ng check kill
  sudo airmon-ng start wlxe84e06ad5857
  
  # Configure interface settings
  sudo ip link set wlan0mon down
  sudo iw dev wlan0mon set type monitor
  sudo ip link set wlan0mon up
  sudo iw dev wlan0mon set channel 6

## Data Analysis
### Wireshark Filters
For analysis, use the following BSSID filter to isolate rogue AP traffic:
  wlan.bssid == C83A35C2E0A2

### Running Parser Scripts
The included bash scripts automate the extraction of security parameters and connection 
timelines. Ensure scripts are executable:

  chmod +x extract_security_summary.sh packet_timeline.sh

  # Generate results summary
  ./extract_security_summary.sh BASELINE.pcapng results.csv
  ./extract_security_summary.sh PMF.pcapng results.csv
  ./extract_security_summary.sh TKIP.pcapng results.csv
  ./extract_security_summary.sh WPA3.pcapng results.csv

  # Generate chronological packet timelines
  ./packet_timeline.sh BASELINE.pcapng baseline_timeline.csv
  ./packet_timeline.sh PMF.pcapng pmf_timeline.csv
  ./packet_timeline.sh TKIP.pcapng tkip_timeline.csv
  ./packet_timeline.sh WPA3.pcapng wpa3_timeline.csv

## Contents
- Report.pdf: The detailed investigative research report.
- PCAPs/: Raw packet captures (.pcapng) for all conditions.
- Scripts/: extract_security_summary.sh and packet_timeline.sh.
- Results/: Generated CSV files and analysis outputs.
- Screenshots/: Visual evidence of connection sequences and security settings.
- Reference Materials: 
    - "חלק ראשון_19.zip"
    - "wep_s_19.pdf"
    - "WPA_C_s_19.pdf"
    - "SDR_s_19.pdf"
    - "Assignment_2_Wireless_Protocol_Investigation_Lab_A_s_20.pdf"

## Screenshots & Evidence
The `Screenshots/` directory contains visual evidence of the laboratory setup and captured 
handshake sequences:
- `hostapd_config_examples/`: Configuration snippets for Baseline, PMF, TKIP, and WPA3 modes.
- `Handshake_Captures/`: Annotated Wireshark screenshots showing:
    - Beacon/Probe Response security advertisements.
    - Authentication frame exchanges (WPA2 vs. WPA3-SAE).
    - Association requests and status codes.
    - EAPOL 4-Way Handshake messages.
    - Post-connection PMF-protected management frames.
