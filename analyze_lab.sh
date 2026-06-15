#!/bin/bash
# Smart 802.11 Lab Analysis Script (Auto-filters background noise)

INPUT=$1
OUTPUT=$2

if [ ! -s "$OUTPUT" ]; then
    echo "Experiment_Phase,AP_Cipher_Suite,AP_AKM_Suite,AP_PMF_Requirement,Client_Authentication,Client_Association_Request,AP_Association_Response_Status,EAPOL_Packet_Count,Final_Connection_Status" > "$OUTPUT"
fi

EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 0. SMART BSSID DETECTION ---
# Find the exact MAC address of our AP by looking at who sent the Association Response
AP_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ta 2>/dev/null | head -n 1)

if [ -n "$AP_MAC" ]; then
    MAC_FILTER="wlan.bssid == $AP_MAC && "
else
    MAC_FILTER="" # Fallback if no connection occurred
fi

# --- 1. EXTRACT AP SECURITY PARAMETERS (Filtered by our specific AP) ---

CIPHER=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.pcs.type" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
if [[ "$CIPHER" == *"4"* ]]; then
    CIPHER_NAME="CCMP"
elif [[ "$CIPHER" == *"2"* ]]; then
    CIPHER_NAME="TKIP"
else
    CIPHER_NAME="Other/None"
fi

AKM=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.akms.type" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
if [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="PSK (WPA2)"
elif [[ "$AKM" == *"8"* ]]; then
    AKM_NAME="SAE (WPA3)"
else
    AKM_NAME="Other/None"
fi

PMF=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.capabilities.mfpr" -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | head -n 1)
if [[ "$PMF" == *"1"* ]]; then
    PMF_VAL="True"
else
    PMF_VAL="False"
fi

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

echo "Data parsed successfully for: $EXP_NAME (Filtered AP MAC: $AP_MAC)"
