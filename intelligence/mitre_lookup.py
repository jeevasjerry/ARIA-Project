import json
import re

MITRE_FILE = "mitre/enterprise-attack.json"

_mitre_data = None
_techniques = None


def load_mitre_database():
    global _mitre_data

    if _mitre_data is None:
        with open(MITRE_FILE, "r") as file:
            _mitre_data = json.load(file)

    return _mitre_data


def get_techniques():
    global _techniques

    if _techniques is not None:
        return _techniques

    data = load_mitre_database()

    techniques = []

    for obj in data["objects"]:

        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None

        for ref in obj.get("external_references", []):

            if ref.get("source_name") == "mitre-attack":

                external_id = ref.get("external_id")

                if external_id and external_id.startswith("T"):
                    technique_id = external_id
                    break

        if technique_id:

            techniques.append({
                "id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", "")
            })

    _techniques = techniques

    return _techniques


def find_technique(technique_id):

    for technique in get_techniques():

        if technique["id"].lower() == technique_id.lower():
            return technique

    return None

def search_techniques(query, limit=10):

    techniques = get_techniques()

    stop_words = {
        "the", "and", "for", "with", "from",
        "this", "that", "into", "current",
        "command", "system", "information",
        "user", "attacker", "attackers",
        "attempt", "obtain", "check"
    }

    query_words = set(
        word
        for word in re.findall(
            r"\b[a-zA-Z]{3,}\b",
            query.lower()
        )
        if word not in stop_words
    )

    results = []

    for technique in techniques:

        name = technique["name"].lower()
        description = technique["description"].lower()

        score = 0

        # Strong weight for words appearing in technique name
        for word in query_words:

            if word in name:
                score += 5

            elif word in description:
                score += 1

        # Bonus for exact phrase matches
        query_clean = query.lower().strip()

        if query_clean in name:
            score += 10

        if query_clean in description:
            score += 5

        if score > 0:

            results.append({
                "id": technique["id"],
                "name": technique["name"],
                "description": technique["description"],
                "score": score
            })

    results.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return results[:limit]


if __name__ == "__main__":

    print("\nLoading MITRE ATT&CK database...")

    techniques = get_techniques()

    print("Techniques loaded:", len(techniques))

    print("\nTesting search:")

    results = search_techniques(
        "discover current user username"
    )

    for result in results:

        print(
            f'{result["id"]} - '
            f'{result["name"]} '
            f'(score={result["score"]})'
        )
