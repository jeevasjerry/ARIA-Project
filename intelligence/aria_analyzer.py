import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parser import parse_cowrie_log
from llm_analyzer import analyze_command
from mitre_lookup import find_technique


# Initial verified mappings for common Linux commands
COMMAND_MAPPINGS = {
    "whoami": "T1033",
    "uname": "T1082",
    "ls": "T1083",
}


def get_mitre_id(command):

    command = command.strip().lower()

    if command == "whoami":
        return "T1033"

    if command.startswith("uname"):
        return "T1082"

    if command == "ls" or command.startswith("ls "):
        return "T1083"

    if command.startswith("wget "):
        return "T1105"

    if command.startswith("curl "):
        return "T1105"

    return None


def main():

    sessions = parse_cowrie_log("cowrie.json")

    print("\n")
    print("=" * 70)
    print("                 ARIA ATTACK ANALYZER")
    print("=" * 70)

    for session_id, session in sessions.items():

        if not session["commands"]:
            continue

        print("\nSession ID :", session["session_id"])
        print("Attacker   :", session["attacker_ip"])
        print(
            "Target     :",
            f'{session["target_ip"]}:{session["target_port"]}'
        )

        print("-" * 70)

        for command in session["commands"]:

            print("\nCommand:", command)

            try:

                result = analyze_command(command)

                print("Intent   :", result["intent"])
                print("Behavior :", result["behavior"])

                technique_id = get_mitre_id(command)

                if technique_id:

                    technique = find_technique(technique_id)

                    if technique:

                        print("\nMITRE ATT&CK")
                        print("ID       :", technique["id"])
                        print("Technique:", technique["name"])

                else:

                    print("\nMITRE ATT&CK")
                    print("Not mapped")

            except Exception as e:

                print("Analysis error:", e)


if __name__ == "__main__":
    main()
