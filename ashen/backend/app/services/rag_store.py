import chromadb
import requests
import time
from sentence_transformers import SentenceTransformer

embedder = SentenceTransformer("all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path="./chroma_db")

SAMPLE_CVES = [
    {
        "id": "CVE-2021-41773",
        "description": "Apache HTTP Server path traversal on port 80/443. CVSS 7.5. Remote code execution possible.",
        "service": "apache",
        "severity": "high"
    },
    {
        "id": "CVE-2020-0796",
        "description": "SMBGhost vulnerability on port 445. CVSS 10.0. Wormable remote code execution.",
        "service": "smb",
        "severity": "critical"
    },
    {
        "id": "CVE-2015-3306",
        "description": "ProFTPD mod_copy vulnerability on port 21 FTP. Unauthenticated file copy.",
        "service": "ftp",
        "severity": "high"
    },
    {
        "id": "CVE-2018-10933",
        "description": "LibSSH authentication bypass on port 22 SSH. CVSS 9.8.",
        "service": "ssh",
        "severity": "critical"
    },
]


def fetch_nvd_cves(keyword: str, max_results: int = 10) -> list:
    """NVD API se real CVEs fetch karo."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            severity = "medium"
            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"].lower()
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"].lower()
            if cve_id and description:
                cves.append({
                    "id": cve_id,
                    "description": description[:500],
                    "severity": severity,
                    "service": keyword
                })
        return cves
    except Exception as e:
        print(f"NVD fetch error for '{keyword}': {e}")
        return []


def build_cve_store(use_nvd: bool = True):
    """CVE data ChromaDB mein store karo."""
    collection = chroma_client.get_or_create_collection("cve_knowledge")

    if collection.count() > 0:
        print(f"CVE store already has {collection.count()} entries.")
        return collection

    all_cves = list(SAMPLE_CVES)

    if use_nvd:
        print("NVD se real CVEs fetch kar raha hun...")
        keywords = ["FTP", "SSH", "SMB", "Apache", "RDP", "MySQL", "HTTP"]
        for keyword in keywords:
            print(f"  Fetching: {keyword}...")
            nvd_cves = fetch_nvd_cves(keyword, max_results=5)
            all_cves.extend(nvd_cves)
            time.sleep(1)  # NVD rate limit avoid karo
        print(f"Total CVEs fetched: {len(all_cves)}")

    # Duplicates remove karo
    seen = set()
    unique_cves = []
    for cve in all_cves:
        if cve["id"] not in seen:
            seen.add(cve["id"])
            unique_cves.append(cve)

    texts = [cve["description"] for cve in unique_cves]
    embeddings = embedder.encode(texts).tolist()
    ids = [cve["id"] for cve in unique_cves]
    metadatas = [{"severity": c["severity"], "service": c["service"]} for c in unique_cves]

    collection.add(
        documents=texts,
        embeddings=embeddings,
        ids=ids,
        metadatas=metadatas
    )

    print(f"ChromaDB mein {len(unique_cves)} CVEs store ho gayi!")
    return collection


def retrieve_relevant_cves(scan_text: str, top_k: int = 5) -> str:
    """Scan text se related CVEs dhundho."""
    collection = chroma_client.get_or_create_collection("cve_knowledge")

    if collection.count() == 0:
        build_cve_store()

    query_embedding = embedder.encode([scan_text]).tolist()
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(top_k, collection.count())
    )

    if not results["documents"][0]:
        return "No relevant CVE context found."

    context_parts = []
    for doc, meta, cve_id in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["ids"][0]
    ):
        context_parts.append(
            f"- {meta['severity'].upper()}: {doc} (ID: {cve_id})"
        )
    return "\n".join(context_parts)


def refresh_cve_store():
    """Purana store delete karo aur naya banao NVD se."""
    collection = chroma_client.get_or_create_collection("cve_knowledge")
    existing = collection.get()
    if existing["ids"]:
        collection.delete(ids=existing["ids"])
        print("Purana CVE store delete ho gaya.")
    build_cve_store(use_nvd=True)