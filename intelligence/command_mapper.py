import shlex


COMMAND_MAPPINGS = {
    "whoami": "T1033",
    "id": "T1033",
    "w": "T1033",
    "who": "T1033",

    "uname": "T1082",
    "hostname": "T1082",

    "ls": "T1083",
    "find": "T1083",
    "locate": "T1083",

    "ifconfig": "T1016",
    "route": "T1016",
}


def get_mitre_id(command):

    command = command.strip()

    if not command:
        return None

    try:
        parts = shlex.split(command)
    except ValueError:
        return None

    if not parts:
        return None

    base_command = parts[0].split("/")[-1]

    return COMMAND_MAPPINGS.get(base_command)


if __name__ == "__main__":

    test_commands = [
        "whoami",
        "id",
        "uname -a",
        "ls",
        "find / -name passwd",
        "ifconfig",
        "echo hello",
        "what_is_this",
    ]

    for command in test_commands:

        technique = get_mitre_id(command)

        print(f"{command:25} -> {technique}")
