# FeeFix AI layer — policy & architecture

## Free-only policy (hard rule)

FeeFix AI uses **local, open-source models exclusively**:

* ❌ No paid APIs (no OpenAI/Anthropic/Gemini/etc.)
* ❌ No token-gated inference services
* ✅ Open-weight models running in-process (``fastembed`` + quantized ONNX
  ``all-MiniLM-L6-v2``, ~90MB, Apache-2.0)
* ✅ A built-in character n-gram hashed embedder with zero downloads — every
  install, including fully offline servers, is AI-capable
* ✅ Grounded answers: Q&A assembles facts *only* from the verified dataset.
  It cannot hallucinate schemes because it has no world model, only retrieval.

Switch: `FEEFIX_AI_BACKEND = auto|neural|ngram` (default `auto` → neural if
weights are present/downloadable, else n-gram).

## Components

| Module | Job |
|---|---|
| `ai/embeddings.py` | Backend selection, two free embedders, cosine. |
| `ai/lexicon.py` | Hinglish/Benglish expansion lexicon + profile-hint regexes. |
| `ai/search.py` | `SemanticSearch` — scheme documents from structured fields, top-k retrieval. |
| `ai/qa.py` | `QaEngine` — grounded answers with citations; profile-hint detection → real matching engine. |

## Upgrading (still free)

* **Better multilingual embeddings** (V3 ties in): swap `NeuralEmbedder.MODEL`
  for a free multilingual model (e.g. `intfloat/multilingual-e5-small`) —
  one-line change when model weights become available.
* **Local LLM polish**: run a free local server (e.g. Ollama with
  `qwen2.5:0.5b` / `llama3.2:1b` / `gemma2:2b`) *behind* `QaEngine` purely as a
  text polisher — the fact extraction from dataset stays deterministic. Plumb
  it in `qa.py` *after* citation assembly, never before.
* **More signals**: route `ml/ranking` outcome scores into answer ordering.

## Why grounding-before-dev-fluency

Students make financial decisions from these answers. The contract:
**every sentence in an answer must trace back to a dataset field** (+ the
matching engine's own explanations). Fluency upgrades are decorative layers on
top of that hard skeleton.
