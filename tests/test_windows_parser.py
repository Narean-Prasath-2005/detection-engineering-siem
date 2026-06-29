import json
from parsers.windows_parser import normalize_windows_event

FILE = "samples/normalized/windows/TA0006-Credential Access/T1003-Credential dumping/ID4688-4663-4656-LSASS dump with LSASSY (process).json"

with open(FILE, "r") as f:
    events = json.load(f)

for event in events:
    event_id = event["Event"]["System"]["EventID"]["#text"]

    if event_id == "4688":
        normalized = normalize_windows_event(event)
        print(normalized)