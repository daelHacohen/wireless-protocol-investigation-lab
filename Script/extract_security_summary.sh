#!/bin/bash
# Level-100 Ultimate Matrix Script (Filtered & Deduplicated)

INPUT=$1
OUTPUT=$2

if [ ! -s "$OUTPUT" ]; then
    echo "Experiment_Phase,AP_Cipher_Suite,AP_AKM_Suite,AP_PMF_Requirement,Client_Auth_Frames_Count,Client_Association_Status,EAPOL_Packet_Count,PMF_Observed,Final_Connection_Status" > "$OUTPUT"
fi

EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 0. SMART BSSID DETECTION ---
AP_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ta 2>/dev/null | head -n 1)

if [ -n "$AP_MAC" ]; then
    MAC_FILTER="wlan.bssid == $AP_MAC && "
    # Get Client MAC for cleaner filtering
    CLIENT_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ra 2>/dev/null | head -n 1)
else
    MAC_FILTER=""
    CLIENT_MAC=""
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

PMF_CHECK=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5)" -V 2>/dev/null | grep -i "Management Frame Protection Required: True" | head -n 1)
if [ -n "$PMF_CHECK" ]; then
    PMF_VAL="True"
else
    PMF_VAL="False"
fi

# --- 2. EXTRACT CLIENT BEHAVIOR (DEDUPLICATED) ---

# Count Unique Auth frames (ignores retransmissions)
AUTH_COUNT=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x0b && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" -T fields -e wlan.seq | sort -u | wc -l)

if [ "$AUTH_COUNT" -ge 4 ]; then
    AUTH_RES="4 (WPA3 SAE Expected)"
elif [ "$AUTH_COUNT" -ge 2 ]; then
    AUTH_RES="2 (WPA2 Open Expected)"
elif [ "$AUTH_COUNT" -gt 0 ]; then
    AUTH_RES="$AUTH_COUNT"
else
    AUTH_RES="0 (None)"
fi

ASSOC_STATUS=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01 && wlan.ta==$AP_MAC" -T fields -e wlan.fixed.status_code 2>/dev/null | head -n 1)
if [[ "$ASSOC_STATUS" == *"0x0000"* ]] || [[ "$ASSOC_STATUS" == *"0"* ]]; then
    ASSOC_STATUS="0 (Success)"
elif [ -z "$ASSOC_STATUS" ]; then
    ASSOC_STATUS="None"
fi

# EAPOL handling (keeping realistic numbers but filtering only relevant ones)
EAPOL_COUNT=$(tshark -r "$INPUT" -Y "eapol && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" | wc -l)
if [ "$EAPOL_COUNT" -gt 4 ]; then
    CONN_STATUS="Success (w/ Retries)"
elif [ "$EAPOL_COUNT" -eq 4 ]; then
    CONN_STATUS="Success (Clean 4-Way)"
else
    CONN_STATUS="Failed/Incomplete"
fi

PMF_ACTIVE_CHECK=$(tshark -r "$INPUT" -Y "wlan.fc.type == 0 && wlan.fc.protected == 1 && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" 2>/dev/null | head -n 1)
if [ -n "$PMF_ACTIVE_CHECK" ]; then
    PMF_ACTIVE="Yes"
else
    PMF_ACTIVE="No"
fi

# --- 3. APPEND RECORD TO CSV TABLE ---
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH_RES,$ASSOC_STATUS,$EAPOL_COUNT,$PMF_ACTIVE,$CONN_STATUS" >> "$OUTPUT"

echo "Level-100 Parsing Complete for: $EXP_NAME"
