#!/bin/bash
# Complete & Robust 802.11 Lab Analysis Script (Including Probe Responses)

INPUT=$1
OUTPUT=$2

# Create table header if the output file doesn't exist yet
if [ ! -f "$OUTPUT" ]; then
    echo "Experiment,Beacon/Probe_Cipher,Beacon/Probe_AKM,Beacon/Probe_PMF_Req,Auth_Sent,Assoc_Req_Sent,Assoc_Resp_Status,EAPOL_Count,Connection_Status" > "$OUTPUT"
fi

EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 1. EXTRACT AP DATA (From Beacons OR Probe Responses) ---
# Added: wlan.fc.type_subtype == 5 (Probe Response) alongside 8 (Beacon)

CIPHER=$(tshark -r "$INPUT" -Y "(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.pcs.type" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
if [[ "$CIPHER" == *"4"* ]]; then
    CIPHER_NAME="CCMP"
elif [[ "$CIPHER" == *"2"* ]]; then
    CIPHER_NAME="TKIP"
else
    CIPHER_NAME="Other/None"
fi

AKM=$(tshark -r "$INPUT" -Y "(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.akms.type" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
if [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="PSK (WPA2)"
elif [[ "$AKM" == *"8"* ]]; then
    AKM_NAME="SAE (WPA3)"
else
    AKM_NAME="Other/None"
fi

PMF=$(tshark -r "$INPUT" -Y "(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.capabilities.mfpr" -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | head -n 1)
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

# --- 3. WRITE TO CSV ---
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH,$ASSOC_REQ,$ASSOC_STATUS,$EAPOL_COUNT,$CONN_STATUS" >> "$OUTPUT"

echo "Data extracted successfully (Beacons + Probe Responses) for: $EXP_NAME"
