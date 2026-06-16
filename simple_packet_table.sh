#!/bin/bash

PCAP="$1"
OUTPUT="$2"

if [ -z "$PCAP" ]; then
    echo "Usage: ./simple_packet_table.sh <input.pcapng> [output.csv]"
    exit 1
fi

if [ -z "$OUTPUT" ]; then
    OUTPUT="packet_table.csv"
fi

echo "Frame,Time,Type/Subtype,Transmitter,Receiver" > "$OUTPUT"

probe_req_seen=0
probe_resp_seen=0
assoc_req_seen=0
assoc_resp_seen=0
auth_count=0

tshark -r "$PCAP" \
-Y "wlan.fc.type_subtype==0x04 || \
    wlan.fc.type_subtype==0x05 || \
    wlan.fc.type_subtype==0x0b || \
    wlan.fc.type_subtype==0x00 || \
    wlan.fc.type_subtype==0x01 || \
    eapol" \
-T fields \
-e frame.number \
-e frame.time_relative \
-e _ws.col.Info \
-e wlan.ta \
-e wlan.ra |
while IFS=$'\t' read -r FRAME TIME INFO TA RA
do

    TYPE=""

    if [[ "$INFO" == *"Probe Request"* ]]; then

        if [ $probe_req_seen -eq 1 ]; then
            continue
        fi

        probe_req_seen=1
        TYPE="Probe Request"

    elif [[ "$INFO" == *"Probe Response"* ]]; then

        if [ $probe_resp_seen -eq 1 ]; then
            continue
        fi

        probe_resp_seen=1
        TYPE="Probe Response"

    elif [[ "$INFO" == *"Authentication"* ]]; then

        if [ $auth_count -ge 2 ]; then
            continue
        fi

        auth_count=$((auth_count + 1))
        TYPE="Authentication"

    elif [[ "$INFO" == *"Association Request"* ]]; then

        if [ $assoc_req_seen -eq 1 ]; then
            continue
        fi

        assoc_req_seen=1
        TYPE="Association Request"

    elif [[ "$INFO" == *"Association Response"* ]]; then

        if [ $assoc_resp_seen -eq 1 ]; then
            continue
        fi

        assoc_resp_seen=1
        TYPE="Association Response"

    elif [[ "$INFO" == *"Message 1 of 4"* ]]; then
        TYPE="EAPOL M1"

    elif [[ "$INFO" == *"Message 2 of 4"* ]]; then
        TYPE="EAPOL M2"

    elif [[ "$INFO" == *"Message 3 of 4"* ]]; then
        TYPE="EAPOL M3"

    elif [[ "$INFO" == *"Message 4 of 4"* ]]; then
        TYPE="EAPOL M4"

    else
        continue
    fi

    echo "\"$FRAME\",\"$TIME\",\"$TYPE\",\"$TA\",\"$RA\"" >> "$OUTPUT"

done

echo "Created: $OUTPUT"