from pymongo import MongoClient
from datetime import datetime


MONGO_URI = "mongodb://127.0.0.1:27017"

client = MongoClient(MONGO_URI)
db = client["aria"]
commands_collection = db["commands"]


def analyze_session(session_id):

    records = list(
        commands_collection.find(
            {"session": str(session_id)}
        ).sort("timestamp", 1)
    )

    if not records:
        return None

    first = records[0]
    last = records[-1]

    # --------------------------------------------------
    # Basic session information
    # --------------------------------------------------

    session = {
        "session": str(session_id),
        "src_ip": first.get("src_ip"),
        "src_port": first.get("src_port"),
        "dst_ip": first.get("dst_ip"),
        "dst_port": first.get("dst_port"),

        "start_time": first.get("timestamp"),
        "end_time": last.get("timestamp"),

        "command_count": len(records),

        "commands": [],
        "mitre_techniques": []
    }


    # --------------------------------------------------
    # Calculate session duration
    # --------------------------------------------------

    if (
        isinstance(first.get("timestamp"), datetime)
        and isinstance(last.get("timestamp"), datetime)
    ):

        duration = (
            last["timestamp"] -
            first["timestamp"]
        ).total_seconds()

        session["duration_seconds"] = duration

    else:

        session["duration_seconds"] = None


    # --------------------------------------------------
    # Process commands
    # --------------------------------------------------

    techniques = {}

    for record in records:

        command_data = {
            "timestamp": record.get("timestamp"),
            "command": record.get("command"),
            "intent": record.get("intent"),
            "behavior": record.get("behavior"),
            "mitre": record.get("mitre")
        }

        session["commands"].append(
            command_data
        )


        # ----------------------------------------------
        # Collect MITRE techniques
        # ----------------------------------------------

        mitre = record.get("mitre")

        if mitre and mitre.get("id"):

            technique_id = mitre["id"]

            if technique_id not in techniques:

                techniques[technique_id] = {
                    "id": technique_id,
                    "name": mitre.get("name"),
                    "commands": []
                }

            techniques[
                technique_id
            ]["commands"].append(
                record.get("command")
            )


    session["mitre_techniques"] = list(
        techniques.values()
    )


    return session


# ======================================================
# TEST
# ======================================================

if __name__ == "__main__":

    session_id = input(
        "Enter session ID: "
    ).strip()

    result = analyze_session(
        session_id
    )

    if not result:

        print(
            f"No records found for session {session_id}"
        )

    else:

        print("\n==============================")
        print("ARIA SESSION ANALYSIS")
        print("==============================")

        print(
            f"Session      : {result['session']}"
        )

        print(
            f"Source IP    : {result['src_ip']}"
        )

        print(
            f"Source Port  : {result['src_port']}"
        )

        print(
            f"Destination  : "
            f"{result['dst_ip']}:{result['dst_port']}"
        )

        print(
            f"Commands     : "
            f"{result['command_count']}"
        )

        print(
            f"Duration     : "
            f"{result['duration_seconds']} seconds"
        )


        print("\nCommands:")

        for command in result["commands"]:

            print(
                f"  {command['command']}"
            )


        print("\nMITRE Techniques:")

        for technique in result[
            "mitre_techniques"
        ]:

            print(
                f"  {technique['id']} - "
                f"{technique['name']}"
            )

            print(
                f"    Commands: "
                f"{', '.join(technique['commands'])}"
            )
