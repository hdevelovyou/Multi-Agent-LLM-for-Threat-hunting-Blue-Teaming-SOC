import chromadb
from sentence_transformers import SentenceTransformer


class Retriever:
    def __init__(self, db_path="./chroma_db", collection_name="threat_intel"):
        """Initialize Threat Intelligence Retriever"""
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_collection(collection_name)
    
    def search(self, query, n_results=3):
        """Search threat intelligence database"""
        query_embedding = self.model.encode([query]).tolist()
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=n_results
        )
        return results
    
    def pretty_print(self, results):
        """Pretty print search results"""
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        
        for i, (doc, meta) in enumerate(zip(docs, metas)):
            print(f"\n===== RESULT {i+1} =====")
            print(f"Type: {meta.get('type')}")
            print(doc)


if __name__ == "__main__":
    retriever = Retriever()
    while True:
        query = input("\nEnter query: ")

        if query.lower() in ["exit", "quit"]:
            break

        results = retriever.search(query)
        retriever.pretty_print(results)
