
"""Simple, deterministic retrieval over local synthetic documents."""

from pathlib import Path
import re

DOCUMENTS_DIR = Path(__file__).resolve().parent.parent / "data" / "documents"


def tokenize(text: str) -> set[str]:
    """Normalize text into a set of simple word tokens."""
    return set(re.findall(r"\b[a-zA-Z0-9_-]+\b", text.lower()))


def load_documents() -> list[dict[str, str]]:
    """Load local text documents in a stable order."""
    documents = []

    for path in sorted(DOCUMENTS_DIR.glob("*.txt")):
        documents.append({
            "source": path.name,
            "text": path.read_text(encoding="utf-8"),
        })

    return documents


def retrieve(query: str, top_k: int = 2) -> list[dict[str, str | int]]:
    """Rank documents by query-token overlap."""
    query_tokens = tokenize(query)
    ranked = []

    for document in load_documents():
        document_tokens = tokenize(document["text"])
        score = len(query_tokens & document_tokens)

        if score > 0:
            ranked.append({
                **document,
                "score": score,
            })

    ranked.sort(key=lambda item: (-item["score"], item["source"]))
    return ranked[:max(0, top_k)]

