def get_field(data_list, field_name):
    for item in data_list:
        if item.get("@Name") == field_name:
            return item.get("#text")
    return None


def normalize_windows_event(event):
    event_data = event["Event"]["EventData"]["Data"]

    normalized = {
        "event_id": event["Event"]["System"]["EventID"]["#text"],
        "timestamp": event["Event"]["System"]["TimeCreated"]["@SystemTime"],
        "hostname": event["Event"]["System"]["Computer"],
        "username": get_field(event_data, "SubjectUserName"),
        "process_name": get_field(event_data, "NewProcessName"),
        "command_line": get_field(event_data, "CommandLine")
    }

    return normalized