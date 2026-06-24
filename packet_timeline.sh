#!/bin/bash
# Advanced 802.11 Packet Sequence Extractor (WPA2 & WPA3 SAE Support)

PCAP="$1"
OUTPUT="$2"

if [ -z "$PCAP" ]; then
    echo "Usage: ./packet_timeline.sh <input.pcapng> [output.csv]"
    exit 1
fi

if [ -z "$OUTPUT" ]; then
    OUTPUT="packet_timeline_$(basename "$PCAP" .pcapng).csv"
fi

# Create CSV Headers
echo "Frame,Time_Relative,Protocol_Stage,Details,Transmitter_MAC,Receiver_MAC" > "$OUTPUT"

echo "Extracting sequence from $PCAP..."

# We filter for: Probe Req(4), Probe Resp(5), Auth(11), Assoc Req(0), Assoc Resp(1), Action/PMF(13) and EAPOL
tshark -r "$PCAP" \
-Y "wlan.fc.type_subtype==0x04 || \
    wlan.fc.type_subtype==0x05 || \
    wlan.fc.type_subtype==0x0b || \
    wlan.fc.type_subtype==0x00 || \
    wlan.fc.type_subtype==0x01 || \
    wlan.fc.type_subtype==0x0d || \
    eapol" \
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

    # 1. Probe Phase
    if [[ "$INFO" == *"Probe Request"* ]]; then
        STAGE="1. Discovery"
        DETAILS="Probe Request"
    elif [[ "$INFO" == *"Probe Response"* ]]; then
        STAGE="1. Discovery"
        DETAILS="Probe Response"

    # 2. Authentication Phase (Supports WPA2 Open and WPA3 SAE)
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
        STAGE="4. Key Exchange (EAPOL)"
        DETAILS="EAPOL Message 1"
    elif [[ "$INFO" == *"Message 2 of 4"* ]]; then
        STAGE="4. Key Exchange (EAPOL)"
        DETAILS="EAPOL Message 2"
    elif [[ "$INFO" == *"Message 3 of 4"* ]]; then
        STAGE="4. Key Exchange (EAPOL)"
        DETAILS="EAPOL Message 3"
    elif [[ "$INFO" == *"Message 4 of 4"* ]]; then
        STAGE="4. Key Exchange (EAPOL)"
        DETAILS="EAPOL Message 4"

    # 5. Management Frame Protection (PMF)
    elif [[ "$INFO" == *"Action"* ]]; then
        # Action frames often appear after connection when PMF is on
        STAGE="5. Management / PMF"
        DETAILS="Action Frame (Possible SA Query/Protected)"

    else
        continue
    fi

    # Write to CSV
    echo "\"$FRAME\",\"$TIME\",\"$STAGE\",\"$DETAILS\",\"$TA\",\"$RA\"" >> "$OUTPUT"

done

echo "Done! Sequence saved to: $OUTPUT"
