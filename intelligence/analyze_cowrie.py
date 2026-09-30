import json
import os
import sys

# Allow imports from intelligence/
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cowrie_parser import extract_commands
from attack_analyzer import analyze_attack


OUTPUT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "analysis_results.json"
)


def main():

    print("=" * 70)
    print("ARIA - COWRIE ATTACK INTELLIGENCE ANALYZER")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. Extract commands from Cowrie
    # ---------------------------------------------------------

    commands = extract_commands()

    print(f"\nCommands found: {len(commands)}")

    if not commands:
        print("No commands found.")
        return

    # ---------------------------------------------------------
    # 2. Cache analysis for repeated commands
    # ---------------------------------------------------------

    cache = {}

    results = []

    # ---------------------------------------------------------
    # 3. Analyze every command
    # ---------------------------------------------------------

    for index, item in enumerate(commands, start=1):

        command = item["command"]

        print("\n" + "-" * 70)
        print(f"[{index}/{len(commands)}] COMMAND: {command}")
        print(f"Session: {item['session']}")
        print(f"Source : {item['src_ip']}")
        print("-" * 70)

        # Reuse analysis if command was already seen
        if command in cache:

            print("Using cached analysis...")

            analysis = cache[command]

        else:

            print("Running Qwen + MITRE analysis...")

            analysis = analyze_attack(command)

            cache[command] = analysis

        # -----------------------------------------------------
        # Combine Cowrie metadata + intelligence
        # -----------------------------------------------------

        result = {
            "session": item["session"],
            "timestamp": item["timestamp"],
            "src_ip": item["src_ip"],
            "src_port": item["src_port"],
            "dst_ip": item["dst_ip"],
            "dst_port": item["dst_port"],
            "command": command,

            "intent": analysis.get("intent"),
            "behavior": analysis.get("behavior"),

            "mitre": analysis.get("mitre")
        }

        results.append(result)

        # -----------------------------------------------------
        # Display result
        # -----------------------------------------------------

        print(f"Intent   : {result['intent']}")
        print(f"Behavior : {result['behavior']}")

        mitre = result.get("mitre")

        if mitre:

            print(f"MITRE ID : {mitre.get('id')}")
            print(f"Technique: {mitre.get('name')}")
            print(f"Score    : {mitre.get('score')}")
            print(f"Status   : {mitre.get('status')}")

        else:

            print("MITRE    : None")

    # ---------------------------------------------------------
    # 4. Save results
    # ---------------------------------------------------------

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        json.dump(
            results,
            f,
            indent=4
        )

    # ---------------------------------------------------------
    # 5. Summary
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

    print(f"\nTotal commands : {len(commands)}")
    print(f"Unique commands: {len(cache)}")
    print(f"Results saved  : {OUTPUT_FILE}")

    print("\nMITRE techniques detected:")

    techniques = {}

    for result in results:

        mitre = result.get("mitre")

        if not mitre:
            continue

        technique_id = mitre.get("id")
        technique_name = mitre.get("name")

        if technique_id:

            techniques[technique_id] = technique_name

    for technique_id, technique_name in techniques.items():

        print(
            f"  {technique_id} - {technique_name}"
        )


if __name__ == "__main__":
    main()
