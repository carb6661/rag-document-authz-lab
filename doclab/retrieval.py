"""Exact keyword ranking of already-authorized snapshots; no model or remote I/O."""
def score_document(document, terms):
    title = document["title"].casefold()
    text = document["text"].casefold()
    matched = [term for term in terms if term in title or term in text]
    if not matched:
        return None
    return {
        "document_id":document["id"], "title":document["title"], "version":document["version"],
        "score":sum(title.count(term) + text.count(term) for term in matched),
        "matched_terms":matched, "snippet":document["text"][:240],
        "citation":{"document_id":document["id"], "version":document["version"]},
    }


def rank_authorized(documents, terms, top_k):
    hits = [hit for document in documents if (hit := score_document(document, terms)) is not None]
    return sorted(hits, key=lambda hit:(-hit["score"], hit["document_id"]))[:top_k]
