#!/bin/bash
# The Ultimate 802.11 Lab Analysis Script (GUI-Text Matching for PMF)

INPUT=$1
OUTPUT=$2

if [ ! -s "$OUTPUT" ]; then
    echo "Experiment_Phase,AP_Cipher_Suite,AP_AKM_Suite,AP_PMF_Requirement,Client_Authentication,Client_Association_Request,AP_Association_Response_Status,EAPOL_Packet_Count,Final_Connection_Status" > "$OUTPUT"
fi

EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 0. SMART BSSID DETECTION ---
AP_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ta 2>/dev/null | head -n 1)

if [ -n "$AP_MAC" ]; then
    MAC_FILTER="wlan.bssid == $AP_MAC && "
else
    MAC_FILTER=""
fi

# --- 1. EXTRACT AP SECURITY PARAMETERS ---

CIPHER=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.pcs.type" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
if [[ "$CIPHER" == *"4"* ]]; then
    CIPHER_NAME="CCMP"
elif [[ "$CIPHER" == *"2"* ]]; then
    CIPHER_NAME="TKIP"
else
    CIPHER_NAME="Other/None"
fi

AKM=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.akms.type" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
if [[ "$AKM" == *"8"* ]] && [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="WPA3 Transition (PSK+SAE)"
elif [[ "$AKM" == *"8"* ]]; then
    AKM_NAME="SAE (WPA3)"
elif [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="PSK (WPA2)"
else
    AKM_NAME="Other/None"
fi

# --- THE BULLETPROOF PMF FIX ---
# Instead of pulling the field, we print the verbose tree (-V) and grep for the exact text from your screenshot.
PMF_CHECK=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5)" -V 2>/dev/null | grep -i "Management Frame Protection Required: True" | head -n 1)

if [ -n "$PMF_CHECK" ]; then
    PMF_VAL="True"
else
    PMF_VAL="False"
fi
# -------------------------------

# --- 2. EXTRACT CLIENT BEHAVIOR ---

AUTH=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x0b" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")

ASSOC_REQ=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x00" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")

ASSOC_STATUS=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.fixed.status_code 2>/dev/null | head -n 1)
if [[ "$ASSOC_STATUS" == *"0x0000"* ]] || [[ "$ASSOC_STATUS" == *"0"* ]]; then
    ASSOC_STATUS="0 (Success)"
elif [ -z "$ASSOC_STATUS" ]; then
    ASSOC_STATUS="None"
fi

EAPOL_COUNT=$(tshark -r "$INPUT" -Y "eapol" | wc -l)
if [ "$EAPOL_COUNT" -ge 4 ]; then
    CONN_STATUS="Success"
else
    CONN_STATUS="Failed"
fi

# --- 3. APPEND RECORD TO CSV TABLE ---
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH,$ASSOC_REQ,$ASSOC_STATUS,$EAPOL_COUNT,$CONN_STATUS" >> "$OUTPUT"

echo "Parsed successfully: $EXP_NAME (Filtered using AP MAC: $AP_MAC)"
