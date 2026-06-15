#!/bin/bash
# Advanced 802.11 Lab Analysis Script

INPUT=$1
OUTPUT=$2

# Create table header if file doesn't exist
if [ ! -f "$OUTPUT" ]; then
    echo "Experiment,Beacon_Cipher,Beacon_AKM,Beacon_PMF_Req,Auth_Sent,Assoc_Req_Sent,Assoc_Resp_Status,EAPOL_Count,Connection_Status" > "$OUTPUT"
fi

EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 1. EXTRACT BEACON DATA (What the AP broadcasts) ---
# Extract Cipher Suite (e.g., CCMP, TKIP)
CIPHER=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
[ "$CIPHER" == "4" ] && CIPHER_NAME="CCMP" || CIPHER_NAME="TKIP/Other"

# Extract AKM (Authentication and Key Management)
AKM=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
[ "$AKM" == "2" ] && AKM_NAME="PSK (WPA2)"
[ "$AKM" == "8" ] && AKM_NAME="SAE (WPA3)"

# Extract PMF Required flag
PMF=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | head -n 1)
[ "$PMF" == "1" ] && PMF_VAL="True" || PMF_VAL="False"

# --- 2. EXTRACT CLIENT BEHAVIOR ---
AUTH=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x0b" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")
ASSOC_REQ=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x00" -q -z io,phs | grep -q "wlan" && echo "Yes" || echo "No")
ASSOC_STATUS=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.fixed.status_code 2>/dev/null | head -n 1)
[ "$ASSOC_STATUS" == "0x0000" ] && ASSOC_STATUS="0 (Success)"

EAPOL_COUNT=$(tshark -r "$INPUT" -Y "eapol" | wc -l)
if [ "$EAPOL_COUNT" -ge 4 ]; then
    CONN_STATUS="Success"
else
    CONN_STATUS="Failed"
fi

# Append to CSV
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH,$ASSOC_REQ,$ASSOC_STATUS,$EAPOL_COUNT,$CONN_STATUS" >> "$OUTPUT"
echo "Processed $EXP_NAME successfully."
