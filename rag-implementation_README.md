# RAG Implementation README

## Overview
This update adds and stabilizes the backend AI + RAG pipeline for ASHEN.
The goal is to generate attack recommendations using:
- scan context from ASHEN,
- retrieved CVE context from ChromaDB,
- local LLM generation through Ollama.

## What Was Implemented

### 1) RAG Service (new location)
- `rag_store.py` is now under `ashen/backend/app/services/rag_store.py`.
- It handles:
  - CVE seed data,
  - optional NVD CVE fetch,
  - embedding generation (`sentence-transformers`),
  - ChromaDB storage/retrieval,
  - context return for prompts.

### 2) Attack Recommendation Integration
- `attack_recommender.py` now uses `retrieve_relevant_cves(...)` from the new RAG service location.
- RAG context is merged into prompt input before LLM generation.
- Streaming and non-streaming recommendation paths both use the updated flow.

### 3) AI Model Configuration
- Default Ollama model updated to `llama3.2` in backend services.
- API responses now report the active configured model value.
- Authenticated AI route smoke tests succeeded with `llama3.2`.

### 4) Supporting Test/Verification
- Added/used RAG test module:
  - `ashen/backend/app/test_rag.py`
- Verified:
  - CVE store build,
  - retrieval output,
  - authenticated attack recommendation route.

## Files Included In This Work
- `ashen/backend/app/services/rag_store.py`
- `ashen/backend/app/services/attack_recommender.py`
- `ashen/backend/app/services/ollama_client.py`
- `ashen/backend/app/api/ai.py`
- `ashen/backend/app/test_rag.py`
- `ashen/backend/requirements.txt`

## Run Instructions

### Install dependencies
From `ashen/backend`:

```bash
python -m pip install -r requirements.txt
```

### Pull model (first time only)

```bash
ollama pull llama3.2
```

### Run RAG test
From `ashen/backend`:

```bash
python -m app.test_rag
```

## Notes and Troubleshooting
- If `python -m app.test_rag` fails with `No module named app`, you are running from the wrong folder.
  - Run it from `ashen/backend`.
- If recommendation takes a long time on first run:
  - embedding model download + CVE store creation are cold-start costs,
  - later calls are much faster for retrieval.
- If AI call fails with model not found (HTTP 404 from Ollama):
  - ensure `llama3.2` is pulled.

## Current Branch
- `backend-ai-rag-implementation`

## Commit Identity Requested
- Name: `MaheenNaeem29`
- Email: `maheennaeem94@gmail.com`
