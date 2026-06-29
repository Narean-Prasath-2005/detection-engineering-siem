import json

from parsers.windows_parser import normalize_windows_event
from core.detector import detect_event


FILE = (
    "samples/normalized/windows/"
    "TA0006-Credential Access/"
    "T1003-Credential dumping/"
    "ID4688-4663-4656-LSASS dump with LSASSY (process).json"
)

with open(FILE, "r") as f:
    events = json.load(f)


for raw_event in events:

    event_id = raw_event["Event"]["System"]["EventID"]["#text"]

    if event_id != "4688":
        continue

    event = normalize_windows_event(raw_event)

    alerts = detect_event(event)

    for alert in alerts:

        print("\n========== ALERT ==========")

        for key, value in alert.items():
            print(f"{key}: {value}")