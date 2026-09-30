import os
import sys
import json


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

COWRIE_FILE = os.path.join(
    BASE_DIR,
    "cowrie.json"
)


# ============================================================
# EXTRACT COMMANDS FROM COWRIE
# ============================================================

def extract_commands():

    commands = []

    with open(
        COWRIE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                continue


            # Only attacker command events
            if event.get("eventid") != "cowrie.command.input":
                continue


            command = event.get("input")

            if not command:
                continue


            commands.append({
                "session": event.get("session"),
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dst_ip": event.get("dst_ip"),
                "dst_port": event.get("dst_port"),
                "command": command
            })


    return commands


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    commands = extract_commands()


    print("=" * 60)
    print("COWRIE COMMAND PARSER")
    print("=" * 60)

    print(
        f"\nTotal commands found: {len(commands)}\n"
    )


    for item in commands:

        print(
            f'[{item["timestamp"]}] '
            f'Session={item["session"]} '
            f'Source={item["src_ip"]} '
            f'Command={item["command"]}'
        )
