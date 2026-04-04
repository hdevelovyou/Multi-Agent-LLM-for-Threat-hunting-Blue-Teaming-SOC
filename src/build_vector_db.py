import json
import chromadb
from sentence_transformers import SentenceTransformer


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

cve_data = load_json("../data/cleanNVD_cve.json")
attack_data = load_json("../data/mitre_attack_dataset.json")

print("CVE:", len(cve_data))
print("ATTACK:", len(attack_data))

def format_cve(cve):
    return f"""
CVE ID: {cve['id']}
Description: {cve['text']}
CWE: {cve['cwe']}
Severity: {cve['severity']}
"""

def format_attack(t):
    return f"""
Technique ID: {t['id']}
Name: {t['name']}
Tactics: {', '.join(t['tactics'])}
Description: {t['text']}
"""

documents = []
metadatas = []
ids = []

# CVE
for i, cve in enumerate(cve_data):
    documents.append(format_cve(cve))
    metadatas.append({"type": "cve"})
    ids.append(f"cve_{i}")

# ATTACK
for i, atk in enumerate(attack_data):
    documents.append(format_attack(atk))
    metadatas.append({"type": "attack"})
    ids.append(f"attack_{i}")

# load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

# create ChromaDB client
client = chromadb.PersistentClient(path="./chroma_db")

collection = client.create_collection("threat_intel")

# embed documents
embeddings = model.encode(documents).tolist()

# add vào DB - batch by 500 items
batch_size = 500
for i in range(0, len(documents), batch_size):
    end_idx = min(i + batch_size, len(documents))
    collection.add(
        documents=documents[i:end_idx],
        embeddings=embeddings[i:end_idx],
        metadatas=metadatas[i:end_idx],
        ids=ids[i:end_idx]
    )
    print(f"Added {end_idx}/{len(documents)} documents")

print("Vector DB built!")