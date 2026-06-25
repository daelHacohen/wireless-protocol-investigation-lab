#!/bin/bash

# הגדרת משתני הקלט: קובץ ה-PCAP לקריאה ונתיב לקובץ ה-CSV שייווצר
PCAP="$1"
OUTPUT="$2"

# בדיקה אם המשתמש סיפק קובץ קלט; אם לא, מדפיסים הוראות שימוש ויוצאים מהסקריפט
if [ -z "$PCAP" ]; then
    echo "Usage: ./simple_packet_table.sh <input.pcapng> [output.csv]"
    exit 1
fi

# אם המשתמש לא הגדיר שם לקובץ הפלט, נקבע שם ברירת מחדל
if [ -z "$OUTPUT" ]; then
    OUTPUT="packet_table.csv"
fi

# יצירת קובץ הפלט וכתיבת שורת הכותרות (מספר פריים, זמן יחסי, סוג הפקטה, כתובת השולח וכתובת המקבל)
echo "Frame,Time,Type/Subtype,Transmitter,Receiver" > "$OUTPUT"

# אתחול משתני בקרה (דגלים) שמטרתם להבטיח שנשמור רק את הפקטה הראשונה מכל סוג (מניעת כפילויות)
probe_req_seen=0
probe_resp_seen=0
assoc_req_seen=0
assoc_resp_seen=0
auth_count=0

# --- התיקון: משתני בקרה חדשים לסינון כפילויות של EAPOL ---
# דגלים אלו מבטיחים שנסנן הודעות כפולות של לחיצת היד המרובעת (4-Way Handshake) ונתעד רק אחת מכל שלב
m1_seen=0
m2_seen=0
m3_seen=0
m4_seen=0

# --- התיקון: הוספת wlan.fc.retry == 0 לסינון שידורים חוזרים ---
# הרצת tshark לחילוץ פקטיות. הסינון wlan.fc.retry == 0 מבטיח שנתעלם מפקטיות שנשלחו שוב עקב הפרעות ברשת.
# פילטר ה-Y מסנן רק סוגי פריים ספציפיים: Probe Req (0x04), Probe Resp (0x05), Authentication (0x0b),
# Association Req (0x00), Association Resp (0x01), או פקטיות הצפנה מסוג eapol.
tshark -r "$PCAP" \
-Y "wlan.fc.retry == 0 && ( \
    wlan.fc.type_subtype==0x04 || \
    wlan.fc.type_subtype==0x05 || \
    wlan.fc.type_subtype==0x0b || \
    wlan.fc.type_subtype==0x00 || \
    wlan.fc.type_subtype==0x01 || \
    eapol)" \
-T fields \
-e frame.number \
-e frame.time_relative \
-e _ws.col.Info \
-e wlan.ta \
-e wlan.ra |
while IFS=$'\t' read -r FRAME TIME INFO TA RA
do

    TYPE=""

    # זיהוי פקטיות Probe Request - שלב סריקת הרשת האקטיבי שבו הלקוח מחפש רשתות בסביבה
    if [[ "$INFO" == *"Probe Request"* ]]; then

        if [ $probe_req_seen -eq 1 ]; then
            continue # אם כבר ראינו פריים כזה, נדלג עליו
        fi

        probe_req_seen=1
        TYPE="Probe Request"

    # זיהוי פקטיות Probe Response - תגובת נקודת הגישה ללקוח, המפרטת את יכולות הרשת
    elif [[ "$INFO" == *"Probe Response"* ]]; then

        # התעלמות מתגובות Probe Response שהגיעו לפני שראינו בקשה רשמית מהלקוח
        if [ $probe_req_seen -eq 0 ]; then
            continue
        fi

        if [ $probe_resp_seen -eq 1 ]; then
            continue
        fi

        probe_resp_seen=1
        TYPE="Probe Response"

    # זיהוי פקטיות Authentication - שלב אימות הזהות הראשוני (Open System ב-WPA2 או SAE ב-WPA3)
    elif [[ "$INFO" == *"Authentication"* ]]; then

        # --- התיקון: מאפשרים עד 4 חבילות עבור WPA3 SAE ---
        # ב-WPA2 ישנן 2 פקטיות אימות, אך פרוטוקול SAE של WPA3 דורש 4 פקטיות (שלבי Commit ו-Confirm)
        if [ $auth_count -ge 4 ]; then
            continue
        fi

        auth_count=$((auth_count + 1))
        TYPE="Authentication"

    # זיהוי פקטיות Association Request - בקשת הלקוח להצטרף רשמית לרשת לאחר שאימות הזהות הצליח
    elif [[ "$INFO" == *"Association Request"* ]]; then

        if [ $assoc_req_seen -eq 1 ]; then
            continue
        fi

        assoc_req_seen=1
        TYPE="Association Request"

    # זיהוי פקטיות Association Response - תגובת נקודת הגישה המאשרת או דוחה את ההתחברות ומקצה מזהה (AID)
    elif [[ "$INFO" == *"Association Response"* ]]; then

        if [ $assoc_resp_seen -eq 1 ]; then
            continue
        fi

        assoc_resp_seen=1
        TYPE="Association Response"

    # --- התיקון: מתעלמים מהודעות EAPOL כפולות במהלך לחיצת היד המרובעת ---
    # שלב ה-4-Way Handshake המשמש לייצור מפתחות הצפנה זמניים (PTK) מתוך המפתח הראשי (PMK)
    
    # הודעה 1 מתוך 4: נשלחת מה-AP ללקוח ומכילה את ה-ANonce (מספר אקראי של הנתב)
    elif [[ "$INFO" == *"Message 1 of 4"* ]]; then
        if [ $m1_seen -eq 1 ]; then continue; fi
        m1_seen=1
        TYPE="EAPOL M1"

    # הודעה 2 מתוך 4: נשלחת מהלקוח ל-AP ומכילה את ה-SNonce (מספר אקראי של הלקוח) וקוד שלמות (MIC)
    elif [[ "$INFO" == *"Message 2 of 4"* ]]; then
        if [ $m2_seen -eq 1 ]; then continue; fi
        m2_seen=1
        TYPE="EAPOL M2"

    # הודעה 3 מתוך 4: נשלחת מה-AP ללקוח ומאשרת את ייצור המפתחות, ומעבירה את מפתח הקבוצה (GTK) מוצפן
    elif [[ "$INFO" == *"Message 3 of 4"* ]]; then
        if [ $m3_seen -eq 1 ]; then continue; fi
        m3_seen=1
        TYPE="EAPOL M3"

    # הודעה 4 מתוך 4: נשלחת מהלקוח ל-AP ומאשרת שההצפנה הופעלה בהצלחה משני הצדדים
    elif [[ "$INFO" == *"Message 4 of 4"* ]]; then
        if [ $m4_seen -eq 1 ]; then continue; fi
        m4_seen=1
        TYPE="EAPOL M4"

    # אם הפקטה לא שייכת לאף אחד משלבי ההתחברות החשובים הללו, נתעלם ממנה
    else
        continue
    fi

    # כתיבת שורת הממצא המפונקחת והמסוננת לתוך קובץ ה-CSV
    echo "\"$FRAME\",\"$TIME\",\"$TYPE\",\"$TA\",\"$RA\"" >> "$OUTPUT"
