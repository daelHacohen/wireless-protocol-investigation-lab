# Wireless Protocol Investigation Lab – Assignment 2

**Course:** Wireless and Mobile Network Security  
**Assignment:** Assignment 2 – Evidence-Based 802.11 Security Analysis  
**Group:** Group 6  
**Members:** Noa Bouchnick, Dael Hacohen Waingarten, Shir Bismuth  
**Repository:** `wireless-protocol-investigation-lab`

---

## 1. Project Overview

This repository contains the reproducibility package for our evidence-based 802.11 security investigation lab.

The project investigates how a Wi-Fi client enforces or tolerates changes in security configuration parameters during the network-joining process. The analysis is based on controlled Wi-Fi experiments, monitor-mode packet captures, parser output, annotated packet tables, and manual Wireshark/TShark inspection.

The investigation focuses on identifying where the client continues, rejects, or fails during the following protocol stages:

- Beacon / Probe Response inspection
- Authentication
- Association and RSN parameter selection
- SAE exchange, when WPA3 is used
- EAPOL 4-Way Handshake, when present
- Final connection result

---

## 2. Investigative Claim

The client enforces some security-configuration parameters during the network-joining process, while tolerating changes in others. We identify, from packet traces, where this boundary lies: whether the client proceeds, rejects, or fails during authentication, association, RSN parameter selection, SAE exchange, or EAPOL key establishment.

---

## 3. Experimental Variables

Each experiment changes one security parameter at a time while keeping the rest of the lab setup as stable as possible.

| Condition | Purpose | Main Changed Variable |
|---|---|---|
| Baseline | Verify that the lab works as expected | Same SSID as the saved profile, different BSSID, WPA2-Personal / CCMP |
| PMF | Test client behavior when PMF capability or requirement changes | Protected Management Frames configuration |
| Cipher Suite | Test whether the client accepts or rejects a cipher-suite change | Cipher suite, for example CCMP vs TKIP / mixed mode |
| AKM / WPA3 Transition | Test client behavior when AKM or WPA mode changes | WPA2-PSK vs WPA3-SAE / transition-related configuration |

For every condition, the analysis checks whether the client sent Authentication, whether it sent Association Request, whether Association Response was received and with which status code, whether EAPOL started, and whether the connection completed, failed, or stopped earlier.

---

## 4. Repository Contents

The repository is organized around the required deliverables: raw captures, parser scripts, parser outputs, packet tables, screenshots, and supporting configuration files.

| Path | Description |
|---|---|
| `wireshark_pcapng/` | Raw monitor-mode PCAPNG captures used as packet evidence. |
| `Script/` | Parser and analysis scripts used to extract security parameters and packet timelines. |
| `Summary_table/` | Structured summary tables generated from the captures. |
| `packet_table/` | Annotated packet tables used to connect frame numbers to interpretation. |
| `Photos/` | Screenshots and visual evidence from Wireshark, hostapd, or the lab setup. |
| `Test/` | Experimental files and intermediate testing material. |
| `dnsmasq2.conf` | DHCP/DNS configuration used by the controlled AP environment. |
| `running_instraction` | Additional local run notes and command reminders. |
| `README.md` | Repository guide and reproducibility instructions. |
| `Assignment_2_Wireless_Protocol_Investigation_Lab.pdf` | Assignment requirements. |
| `Wireless_Protocol_Investigation_Lab_Report.pdf` | Experimental Summary Report. |

---

## 5. Hardware and Software Versions

### Hardware

| Component | Device / Role |
|---|---|
| Access Point adapter | Tenda N151 USB Wi-Fi adapter, interface `wlxc83a35c2e0a2` |
| Monitor-mode adapter | EDUP AX3000 Wi-Fi 6 adapter, interface `wlxe84e06ad5857` / `wlan0mon` |
| Client device | The device with the saved Wi-Fi profile used during the experiments. Record the exact model in the final report. |
| AP mode | Controlled software AP using `hostapd` |
| Capture mode | Monitor mode on the experiment channel |

### Software

| Software | Version / Use |
|---|---|
| OS | DragonOS Noble |
| hostapd | v2.10, used to create controlled AP configurations |
| dnsmasq | DHCP/DNS service for the AP network |
| Wireshark | v4.4.2, manual packet inspection |
| TShark | Used by scripts to extract structured packet fields |
| Linux wireless tools | `iw`, `ip`, `airmon-ng`, `tcpdump` |

---

## 6. Lab Setup

The controlled lab uses two Wi-Fi adapters:

1. One adapter runs the controlled AP using `hostapd`.
2. A second adapter runs in monitor mode and captures 802.11 frames on the selected channel.
3. A client device with a saved Wi-Fi profile attempts to connect to the controlled AP.
4. The AP configuration is changed between experiments according to the selected condition.

Basic topology:

```text
+-------------------+          802.11 frames          +-------------------+
| Client device     |  <---------------------------->  | Controlled AP     |
| Saved Wi-Fi       |                                  | hostapd + dnsmasq |
| profile           |                                  | wlxc83a35c2e0a2   |
+-------------------+                                  +-------------------+
          |
          | monitor-mode capture
          v
+-------------------+
| Capture adapter   |
| EDUP AX3000       |
| wlan0mon          |
| Wireshark/TShark  |
+-------------------+
```

---

## 7. Running the Controlled AP

Run the following commands on the machine that hosts the AP adapter.

### 7.1 Configure the AP interface

```bash
sudo ip addr add 192.168.10.1/24 dev wlxc83a35c2e0a2
sudo ip link set wlxc83a35c2e0a2 up
```

### 7.2 Start DHCP/DNS

```bash
sudo dnsmasq -C dnsmasq2.conf
```

### 7.3 Start hostapd

Run the configuration file that matches the current experiment:

```bash
sudo hostapd hostapd_lab_BASELINE.config
```

Other experiment configurations may include:

```bash
sudo hostapd hostapd_lab_with_PMF.config
sudo hostapd hostapd_lab_with_TKIP.config
sudo hostapd hostapd_lab_with_WPA3.config
```

Use only one AP configuration per capture so that each trace represents a single controlled experimental variable.

---

## 8. Capturing Traffic in Monitor Mode

Prepare the monitor adapter and lock it to the experiment channel.

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlxe84e06ad5857

sudo ip link set wlan0mon down
sudo iw dev wlan0mon set type monitor
sudo ip link set wlan0mon up
sudo iw dev wlan0mon set channel 6
```

Start a capture with Wireshark or TShark. Example TShark command:

```bash
sudo tshark -i wlan0mon -w wireshark_pcapng/baseline.pcapng
```

Useful Wireshark display filter for isolating the controlled AP traffic:

```text
wlan.bssid == C8:3A:35:C2:E0:A2
```

If the BSSID is displayed without colons in a specific tool output, use the equivalent format:

```text
wlan.bssid == C83A35C2E0A2
```

---

## 9. Parser and Analysis Scripts

The scripts in `Script/` extract the fields needed to evaluate the investigative claim.

Before running the scripts:

```bash
chmod +x Script/*.sh
```

Example usage:

```bash
./Script/extract_security_summary.sh wireshark_pcapng/BASELINE.pcapng Summary_table/baseline_summary.csv
./Script/extract_security_summary.sh wireshark_pcapng/PMF.pcapng Summary_table/pmf_summary.csv
./Script/extract_security_summary.sh wireshark_pcapng/TKIP.pcapng Summary_table/tkip_summary.csv
./Script/extract_security_summary.sh wireshark_pcapng/WPA3.pcapng Summary_table/wpa3_summary.csv
```

Packet timeline extraction:

```bash
./Script/packet_timeline.sh wireshark_pcapng/BASELINE.pcapng packet_table/baseline_timeline.csv
./Script/packet_timeline.sh wireshark_pcapng/PMF.pcapng packet_table/pmf_timeline.csv
./Script/packet_timeline.sh wireshark_pcapng/TKIP.pcapng packet_table/tkip_timeline.csv
./Script/packet_timeline.sh wireshark_pcapng/WPA3.pcapng packet_table/wpa3_timeline.csv
```

The parser output is used to determine:

- Frame number or packet index
- Timestamp
- Transmitter address
- Receiver address
- BSSID
- Frame type and subtype
- SSID advertisement or selection
- RSN information element details
- AKM suite selector
- Pairwise cipher suite selector
- PMF capable / PMF required bits
- Authentication frames
- Association Request / Association Response
- Association status code
- SAE commit / confirm frames, when present
- EAPOL presence and message progression, when present

---

## 10. Expected Output Files

After running the analysis scripts, the repository should contain structured outputs such as:

```text
Summary_table/baseline_summary.csv
Summary_table/pmf_summary.csv
Summary_table/tkip_summary.csv
Summary_table/wpa3_summary.csv

packet_table/baseline_timeline.csv
packet_table/pmf_timeline.csv
packet_table/tkip_timeline.csv
packet_table/wpa3_timeline.csv
```

These files support the annotated packet table and the claim-to-evidence table in the final report.

---

## 11. Packet Evidence and Manual Verification

The raw PCAPNG files should be opened in Wireshark to verify the packet numbers cited in the report.

Recommended inspection points:

- Beacon frames: advertised SSID, RSN IE, AKM, cipher suites, PMF bits
- Probe Responses: security parameters visible before association
- Authentication frames: whether the client starts authentication
- Association Request: selected RSN parameters from the client
- Association Response: AP status code and acceptance or rejection
- SAE commit / confirm: WPA3-SAE authentication behavior, if present
- EAPOL frames: whether the 4-Way Handshake starts and how far it progresses

Important: screenshots are supporting evidence only. The raw PCAPNG files are the primary evidence and must allow the examiner to verify the cited frames.

---

## 12. Claim-to-Evidence Method

Every major conclusion in the report should be tied to packet-level evidence.

Example structure:

| Claim | Evidence | Explanation |
|---|---|---|
| The AP advertises WPA2-PSK with CCMP in the baseline. | Beacon / Probe Response frame, RSN IE | The RSN element contains the AKM and pairwise cipher suite selectors. |
| The client selected specific RSN parameters. | Association Request frame | The client includes its selected RSN parameters in the Association Request. |
| The connection reached key establishment. | EAPOL frames | EAPOL frames indicate that the association progressed to the 4-Way Handshake stage. |
| The client rejected or stopped before association. | No Association Request after relevant Beacon / Probe Response | The absence of the next state transition is evidence only when the capture window and filtering are controlled. |

---

## 13. Reproducing the Investigation

1. Clone the repository:

```bash
git clone https://github.com/daelHacohen/wireless-protocol-investigation-lab.git
cd wireless-protocol-investigation-lab
```

2. Verify tools are installed:

```bash
hostapd -v
dnsmasq --version
tshark -v
iw --version
```

3. Start the controlled AP for one experiment.
4. Start monitor-mode capture on the selected channel.
5. Attempt to connect the client device to the controlled AP.
6. Save the PCAPNG file using a clear name.
7. Repeat for the next condition, changing only one security parameter.
8. Run the parser scripts.
9. Compare the CSV outputs and verify key frames manually in Wireshark.
10. Use the output files and frame numbers in the final report.

---

## 14. Ethical Scope and Privacy

All experiments in this repository are intended only for an authorized, controlled lab environment.

- The AP was created and controlled by the group.
- The client device was part of the authorized experiment.
- Captures were collected only for the group’s lab network and devices.
- Traffic from unrelated nearby devices, if incidentally captured, must be filtered out and must not be analyzed.
- The project does not attempt to recover real passwords, private messages, or personal data.
- The goal is protocol investigation and evidence-based security analysis, not unauthorized exploitation.

---

## 15. Known Limitations

- Different Wi-Fi adapters, drivers, and client devices may behave differently.
- Some clients may reject a configuration before sending Association Request, making absence of later frames an important but carefully limited observation.
- WPA3-SAE, PMF-required mode, or TKIP/mixed mode may not be supported by all AP/client combinations.
- Monitor-mode capture quality depends on channel lock, driver behavior, distance, and timing.
- PCAPs may include environmental wireless noise; analysis should filter only the controlled AP, client, and experiment channel.
- If a parameter is unsupported by hardware, it should be documented as a lab limitation rather than treated as a failed experiment.




