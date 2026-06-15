#!/bin/bash
# Complete 802.11 Lab Analysis Script for CSV Export

INPUT=$1
OUTPUT=$2

# Create table header if the output file doesn't exist yet
if [ ! -f "$OUTPUT" ]; then
    echo "Experiment_Phase,Beacon_Cipher,Beacon_AKM,Beacon_PMF_Req,Auth_Sent,Assoc_Req_Sent,Assoc_Resp_Status,EAPOL_Count,Connection_Status" > "$OUTPUT"
fi

# Use the file name as the Experiment Phase name (removing the .pcapng extension)
EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 1. EXTRACT BEACON DATA (What the AP broadcasts) ---

# Extract Cipher Suite (Looking for CCMP or TKIP)
CIPHER=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
if [ "$CIPHER" == "4" ]; then
    CIPHER_NAME="CCMP"
elif [ "$CIPHER" == "2" ]; then
    CIPHER_NAME="TKIP"
else
    CIPHER_NAME="Other/None"
fi

# Extract AKM (Authentication and Key Management)
AKM=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
if [ "$AKM" == "2" ]; then
    AKM_NAME="PSK (WPA2)"
elif [ "$AKM" == "8" ]; then
    AKM_NAME="SAE (WPA3)"
else
    AKM_NAME="Other/None"
fi

# Extract PMF Required flag
PMF=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | head -n 1)
if [ "$PMF" == "1" ]; then
    PMF_VAL="True"
else
    PMF_VAL="False"
fi

# --- 2. EXTRACT CLIENT BEHAVIOR ---

# Check if Authentication was sent (Type/Subtype 0x0b)
AUTH=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x0b" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")

# Check if Association Request was sent (Type/Subtype 0x00)
ASSOC_REQ=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x00" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")

# Get Status Code from Association Response (Type/Subtype 0x01)
ASSOC_STATUS=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.fixed.status_code 2>/dev/null | head -n 1)
if [ "$ASSOC_STATUS" == "0x0000" ] || [ "$ASSOC_STATUS" == "0" ]; then
    ASSOC_STATUS="0 (Success)"
elif [ -z "$ASSOC_STATUS" ]; then
    ASSOC_STATUS="None"
fi

# Count EAPOL messages (4-way handshake)
EAPOL_COUNT=$(tshark -r "$INPUT" -Y "eapol" | wc -l)

# Determine Final Connection Status
if [ "$EAPOL_COUNT" -ge 4 ]; then
    CONN_STATUS="Success"
else
    CONN_STATUS="Failed"
fi

# --- 3. WRITE TO CSV ---
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH,$ASSOC_REQ,$ASSOC_STATUS,$EAPOL_COUNT,$CONN_STATUS" >> "$OUTPUT"

echo "Data extracted successfully for: $EXP_NAME"
