from app.services.rag_store import build_cve_store, retrieve_relevant_cves


if __name__ == "__main__":
    print("=== CVE Store Setup ===")
    collection = build_cve_store()
    if collection is None:
        print("RAG dependencies not available. Falling back to keyword retrieval.")

    print("\n=== RAG Retrieval Test ===")
    context = retrieve_relevant_cves("Open port 21 FTP detected")
    print("Retrieved context:\n", context)
