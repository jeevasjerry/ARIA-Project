import os
import pickle

from sentence_transformers import SentenceTransformer
from mitre_lookup import get_techniques


MODEL_NAME = "all-MiniLM-L6-v2"

INDEX_FILE = "mitre/mitre_embeddings.pkl"


def build_index():

    print("\nLoading embedding model...")

    model = SentenceTransformer(MODEL_NAME)

    print("Loading MITRE ATT&CK techniques...")

    techniques = get_techniques()

    texts = []

    for technique in techniques:

        text = (
            technique["name"]
            + ". "
            + technique["description"]
        )

        texts.append(text)

    print("Creating embeddings for", len(texts), "techniques...")

    embeddings = model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=True
    )

    index = {
        "model": MODEL_NAME,
        "techniques": techniques,
        "embeddings": embeddings
    }

    os.makedirs("mitre", exist_ok=True)

    with open(INDEX_FILE, "wb") as file:
        pickle.dump(index, file)

    print("\n====================================")
    print("MITRE EMBEDDING INDEX CREATED")
    print("====================================")
    print("Techniques :", len(techniques))
    print("Index      :", INDEX_FILE)


if __name__ == "__main__":
    build_index()
