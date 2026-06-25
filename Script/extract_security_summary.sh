#!/bin/bash

# משתני קלט ופלט - נתיב לקובץ ה-pcapng ונתיב לקובץ ה-CSV שיווצר
INPUT=$1
OUTPUT=$2

# בדיקה אם קובץ הפלט ריק או לא קיים; אם כן, מייצרים שורת כותרות (Header) לטבלת ה-CSV
if [ ! -s "$OUTPUT" ]; then
    echo "Experiment_Phase,AP_Cipher_Suite,AP_AKM_Suite,AP_PMF_Requirement,Client_Auth_Frames_Count,Client_Association_Status,EAPOL_Packet_Count,PMF_Observed,Final_Connection_Status" > "$OUTPUT"
fi

# חילוץ שם הניסוי מתוך נתיב קובץ הקלט (ללא הסיומת .pcapng)
EXP_NAME=$(basename "$INPUT" .pcapng)

# --- 0. SMART BSSID DETECTION (זיהוי חכם של נקודת הגישה) ---
# פקודה זו מחלצת את כתובת ה-MAC של ה-AP (נתב) מתוך פקטה מסוג Association Response (סוג 0x01)
AP_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ta 2>/dev/null | head -n 1)

# אם נמצאה כתובת ה-MAC של ה-AP, יוצרים פילטר שיסנן רק פקטיות השייכות לרשת הזו (BSSID),
# ומחלצים גם את כתובת ה-MAC של הלקוח (Client) לצורך סינון נקי יותר בהמשך.
if [ -n "$AP_MAC" ]; then
    MAC_FILTER="wlan.bssid == $AP_MAC && "
    CLIENT_MAC=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01" -T fields -e wlan.ra 2>/dev/null | head -n 1)
else
    MAC_FILTER=""
    CLIENT_MAC=""
fi

# --- 1. EXTRACT AP SECURITY PARAMETERS (חילוץ פרמטרי אבטחה של נקודת הגישה) ---
# זיהוי פרוטוקול ההצפנה (Cipher Suite) מתוך פקטיות Beacon (סוג 8) או Probe Response (סוג 5) בשדה RSN
CIPHER=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.pcs.type" -T fields -e wlan.rsn.pcs.type 2>/dev/null | head -n 1)
# ערך 4 מיוצג בתקן כ-CCMP (ההצפנה החזקה המבוססת AES המשמשת ב-WPA2/WPA3)
if [[ "$CIPHER" == *"4"* ]]; then
    CIPHER_NAME="CCMP"
# ערך 2 מיוצג כ-TKIP (הצפנה ישנה ופגיעה של WPA/WEP)
elif [[ "$CIPHER" == *"2"* ]]; then
    CIPHER_NAME="TKIP"
else
    CIPHER_NAME="Other/None"
fi

# זיהוי מנגנון ניהול המפתחות (AKM - Authentication and Key Management) מתוך ה-Beacon/Probe Response
AKM=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5) && wlan.rsn.akms.type" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -n 1)
# אם קיימים גם ערך 8 (SAE) וגם ערך 2 (PSK), הרשת נמצאת במצב מעבר (Transition Mode) התומך ב-WPA2 וב-WPA3 במקביל
if [[ "$AKM" == *"8"* ]] && [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="WPA3 Transition (PSK+SAE)"
# ערך 8 בלבד מסמל WPA3 טהור המשתמש ב-SAE (Simultaneous Authentication of Equals) העמיד בפני התקפות מילון במצב לא מקוון
elif [[ "$AKM" == *"8"* ]]; then
    AKM_NAME="SAE (WPA3)"
# ערך 2 בלבד מסמל WPA2 אישי רגיל המשתמש ב-Pre-Shared Key (מפתח משותף)
elif [[ "$AKM" == *"2"* ]]; then
    AKM_NAME="PSK (WPA2)"
else
    AKM_NAME="Other/None"
fi

# בדיקה האם הגנת פריים ניהוליים (PMF - Protected Management Frames) מוגדרת כחובה ברשת (Required)
# הגנה זו מונעת התקפות מניעת שירות (DoS) נפוצות כמו התקפת ניתוק מזויפת (Deauthentication Attack)
PMF_CHECK=$(tshark -r "$INPUT" -Y "${MAC_FILTER}(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5)" -V 2>/dev/null | grep -i "Management Frame Protection Required: True" | head -n 1)
if [ -n "$PMF_CHECK" ]; then
    PMF_VAL="True"
else
    PMF_VAL="False"
fi

# --- 2. EXTRACT CLIENT BEHAVIOR (חילוץ התנהגות הלקוח וניקוי כפילויות) ---

# ספירת מספרי הרצף (Sequence Numbers) הייחודיים של פקטיות ה-Authentication (סוג 0x0b).
# הסינון באמצעות "sort -u" מבטיח התעלמות מפקטיות שנשלחו שוב עקב בעיות קליטה (Retransmissions)
AUTH_COUNT=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x0b && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" -T fields -e wlan.seq | sort -u | wc -l)

# ניתוח מספר פקטיות ה-Auth כדי להבין באיזה פרוטוקול נעשה שימוש:
# פרוטוקול SAE (של WPA3) דורש לחיצת יד של 4 שלבים (Commit ו-Confirm מכל צד), בעוד WPA2/Open דורש 2 שלבים בלבד
if [ "$AUTH_COUNT" -ge 4 ]; then
    AUTH_RES="4 (WPA3 SAE Expected)"
elif [ "$AUTH_COUNT" -ge 2 ]; then
    AUTH_RES="2 (WPA2 Open Expected)"
elif [ "$AUTH_COUNT" -gt 0 ]; then
    AUTH_RES="$AUTH_COUNT"
else
    AUTH_RES="0 (None)"
fi

# בדיקת קוד הסטטוס (Status Code) מתוך פקטיות ה-Association Response (סוג 0x01) של ה-AP
ASSOC_STATUS=$(tshark -r "$INPUT" -Y "wlan.fc.type_subtype == 0x01 && wlan.ta==$AP_MAC" -T fields -e wlan.fixed.status_code 2>/dev/null | head -n 1)
# קוד 0x0000 או 0 מסמל הצלחה בשלב ההתחברות הראשוני (Association Success)
if [[ "$ASSOC_STATUS" == *"0x0000"* ]] || [[ "$ASSOC_STATUS" == *"0"* ]]; then
    ASSOC_STATUS="0 (Success)"
elif [ -z "$ASSOC_STATUS" ]; then
    ASSOC_STATUS="None"
fi

# בדיקת לחיצת היד המרובעת (4-Way Handshake) באמצעות ספירת פקטיות ה-EAPOL ברשת.
# לחיצת יד נקייה ותקינה לייצור מפתחות הצפנה (PTK) מכילה בדיוק 4 פקטיות
EAPOL_COUNT=$(tshark -r "$INPUT" -Y "eapol && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" | wc -l)
if [ "$EAPOL_COUNT" -gt 4 ]; then
    CONN_STATUS="Success (w/ Retries)" # ההתחברות הצליחה אך היו ניסיונות חוזרים/פקטיות שנפלו
elif [ "$EAPOL_COUNT" -eq 4 ]; then
    CONN_STATUS="Success (Clean 4-Way)" # התחברות נקייה ומושלמת
else
    CONN_STATUS="Failed/Incomplete" # לחיצת היד נכשלה או לא הושלמה (למשל מפתח שגוי או ניתוק באמצע)
fi

# בדיקה בזמן אמת האם PMF פעיל בפועל: מחפשים פריים ניהולי (type 0) שמסומן כמוצפן ומוגן (protected == 1)
PMF_ACTIVE_CHECK=$(tshark -r "$INPUT" -Y "wlan.fc.type == 0 && wlan.fc.protected == 1 && (wlan.ta==$AP_MAC || wlan.ra==$AP_MAC)" 2>/dev/null | head -n 1)
if [ -n "$PMF_ACTIVE_CHECK" ]; then
    PMF_ACTIVE="Yes"
else
    PMF_ACTIVE="No"
fi

# --- 3. APPEND RECORD TO CSV TABLE (שמירת הממצאים) ---
# הזרקת כל הנתונים שחולצו כשורה חדשה לתוך קובץ ה-CSV המרכז את תוצאות הניסויים
echo "$EXP_NAME,$CIPHER_NAME,$AKM_NAME,$PMF_VAL,$AUTH_RES,$ASSOC_STATUS,$EAPOL_COUNT,$PMF_ACTIVE,$CONN_STATUS" >> "$OUTPUT"

echo "Level-100 Parsing Complete for: $EXP_NAME"
