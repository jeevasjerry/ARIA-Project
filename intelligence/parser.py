import json
from datetime import datetime


LOG_FILE = "cowrie.json"


def parse_cowrie_log(log_file):
    sessions = {}

    with open(log_file, "r") as file:

        for line in file:

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            session_id = event.get("session")

            if not session_id:
                continue

            # Create session
            if session_id not in sessions:

                sessions[session_id] = {
                    "session_id": session_id,
                    "attacker_ip": event.get("src_ip"),
                    "attacker_port": event.get("src_port"),
                    "target_ip": event.get("dst_ip"),
                    "target_port": event.get("dst_port"),
                    "start_time": event.get("timestamp"),
                    "end_time": None,
                    "login_attempts": [],
                    "login_success": False,
                    "commands": []
                }

            session = sessions[session_id]

            # End time
            if event.get("eventid") in [
                "cowrie.session.closed",
                "cowrie.session.connection.lost"
            ]:
                session["end_time"] = event.get("timestamp")

            # Login attempts
            if event.get("eventid") == "cowrie.login.failed":

                session["login_attempts"].append({
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "success": False
                })

            elif event.get("eventid") == "cowrie.login.success":

                session["login_success"] = True

                session["login_attempts"].append({
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "success": True
                })

            # Commands
            if event.get("eventid") == "cowrie.command.input":

                command = event.get("input")

                if command:
                    session["commands"].append(command)

    return sessions


def print_sessions(sessions):

    print("\n")
    print("=" * 60)
    print("              ARIA COWRIE SESSION ANALYZER")
    print("=" * 60)

    for session_id, session in sessions.items():

        print("\nSession ID     :", session["session_id"])
        print("Attacker IP    :", session["attacker_ip"])
        print("Attacker Port  :", session["attacker_port"])
        print(
            "Target         :",
            f'{session["target_ip"]}:{session["target_port"]}'
        )

        print("Start Time     :", session["start_time"])
        print("End Time       :", session["end_time"])

        print(
            "Login Status   :",
            "SUCCESS" if session["login_success"] else "UNKNOWN/FAILED"
        )

        print("\nLogin Attempts:")

        if session["login_attempts"]:

            for login in session["login_attempts"]:

                status = "SUCCESS" if login["success"] else "FAILED"

                print(
                    f'  → {login["username"]}/{login["password"]}'
                    f' [{status}]'
                )

        else:
            print("  → None")

        print("\nCommands:")

        if session["commands"]:

            for command in session["commands"]:
                print("  →", command)

        else:
            print("  → None")

        print("-" * 60)


if __name__ == "__main__":

    sessions = parse_cowrie_log(LOG_FILE)

    print_sessions(sessions)
