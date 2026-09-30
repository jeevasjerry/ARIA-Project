import pickle
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

INDEX_FILE = "mitre/mitre_embeddings.pkl"

print("Loading MITRE embedding index...")
with open(INDEX_FILE, "rb") as file:
    index = pickle.load(file)

model = SentenceTransformer(index["model"])

techniques = index["techniques"]
embeddings = index["embeddings"]


def search_mitre(command, top_k=5):
    query_embedding = model.encode(
        [command],
        normalize_embeddings=True
    )

    scores = cosine_similarity(
        query_embedding,
        embeddings
    )[0]

    ranked = scores.argsort()[::-1][:top_k]

    results = []

    for i in ranked:
        results.append({
            "id": techniques[i]["id"],
            "name": techniques[i]["name"],
            "score": float(scores[i])
        })

    return results


if __name__ == "__main__":

    commands = [
        "whoami",
        "ls",
        "uname -a",
        "cat /etc/passwd",
        "ip addr",
        "ps aux",
        "find / -name password.txt"
    ]

    for command in commands:

        print("\n===================================")
        print("COMMAND:", command)
        print("===================================")

        results = search_mitre(command)

        for result in results:
            print(
                f'{result["id"]} - '
                f'{result["name"]} '
                f'(score={result["score"]:.3f})'
            )
