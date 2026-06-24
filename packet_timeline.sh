#!/bin/bash
# Advanced 802.11 Packet Sequence Extractor (Clean & Deduplicated)

PCAP="$1"
OUTPUT="$2"

if [ -z "$PCAP" ]; then
    echo "Usage: ./packet_timeline.sh <input.pcapng> [output.csv]"
    exit 1
fi

if [ -z "$OUTPUT" ]; then
    OUTPUT="packet_timeline_$(basename "$PCAP" .pcapng).csv"
fi

echo "Frame,Time_Relative,Protocol_Stage,Details,Transmitter_MAC,Receiver_MAC" > "$OUTPUT"

echo "Extracting CLEAN sequence from $PCAP..."

# Smart BSSID Detection to filter background noise
AP_MAC=$(tshark -r "$PCAP" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ta 2>/dev/null | head -n 1)
if [ -n "$AP_MAC" ]; then
    MAC_FILTER="(wlan.ta == $AP_MAC || wlan.ra == $AP_MAC) && "
else
    MAC_FILTER=""
fi

probe_req_seen=0
probe_resp_seen=0

# We filter out retransmissions using: wlan.fc.retry == 0
tshark -r "$PCAP" \
-Y "${MAC_FILTER} wlan.fc.retry == 0 && (wlan.fc.type_subtype==0x04 || wlan.fc.type_subtype==0x05 || wlan.fc.type_subtype==0x0b || wlan.fc.type_subtype==0x00 || wlan.fc.type_subtype==0x01 || wlan.fc.type_subtype==0x0d || eapol)" \
-T fields \
-e frame.number \
-e frame.time_relative \
-e _ws.col.Info \
-e wlan.ta \
-e wlan.ra |
while IFS=$'\t' read -r FRAME TIME INFO TA RA
do
    STAGE=""
    DETAILS=""

    # 1. Probe Phase (Show only 1 set)
    if [[ "$INFO" == *"Probe Request"* ]]; then
        if [ $probe_req_seen -eq 1 ]; then continue; fi
        probe_req_seen=1
        STAGE="1. Discovery"
        DETAILS="Probe Request"
    elif [[ "$INFO" == *"Probe Response"* ]]; then
        if [ $probe_resp_seen -eq 1 ]; then continue; fi
        probe_resp_seen=1
        STAGE="1. Discovery"
        DETAILS="Probe Response"

    # 2. Authentication Phase (SAE Aware)
    elif [[ "$INFO" == *"Authentication"* ]]; then
        STAGE="2. Authentication"
        if [[ "$INFO" == *"SAE Commit"* ]]; then
            DETAILS="WPA3 SAE Commit"
        elif [[ "$INFO" == *"SAE Confirm"* ]]; then
            DETAILS="WPA3 SAE Confirm"
        else
            DETAILS="WPA2 Open Authentication"
        fi

    # 3. Association Phase
    elif [[ "$INFO" == *"Association Request"* ]]; then
        STAGE="3. Association"
        DETAILS="Association Request"
    elif [[ "$INFO" == *"Association Response"* ]]; then
        STAGE="3. Association"
        if [[ "$INFO" == *"Status code: Successful"* ]] || [[ "$INFO" == *"Status: Successful"* ]]; then
             DETAILS="Association Response (Success)"
        else
             DETAILS="Association Response"
        fi

    # 4. EAPOL 4-Way Handshake
    elif [[ "$INFO" == *"Message 1 of 4"* ]]; then
        STAGE="4. Key Exchange"
        DETAILS="EAPOL Message 1"
    elif [[ "$INFO" == *"Message 2 of 4"* ]]; then
        STAGE="4. Key Exchange"
        DETAILS="EAPOL Message 2"
    elif [[ "$INFO" == *"Message 3 of 4"* ]]; then
        STAGE="4. Key Exchange"
        DETAILS="EAPOL Message 3"
    elif [[ "$INFO" == *"Message 4 of 4"* ]]; then
        STAGE="4. Key Exchange"
        DETAILS="EAPOL Message 4"

    # 5. Management Frame Protection (PMF)
    elif [[ "$INFO" == *"Action"* ]]; then
        STAGE="5. Management / PMF"
        DETAILS="Encrypted Action Frame"

    else
        continue
    fi

    echo "\"$FRAME\",\"$TIME\",\"$STAGE\",\"$DETAILS\",\"$TA\",\"$RA\"" >> "$OUTPUT"

done

echo "Done! Clean sequence saved to: $OUTPUT"
