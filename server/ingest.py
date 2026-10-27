import json

def read_events(filepath):
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            yield event

if __name__ == "__main__":
    for e in read_events("../mock_events.jsonl"):
        print(e)