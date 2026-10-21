"""Document Privacy Shield core (AMAN Gate 2.0, WP1).

Sanitize a document LOCALLY before any AI sees it. Deterministic policy is the authority; nothing in
this package calls a model, the network, or the advisory ML classifier. Anything unsupported or
uncertain fails closed (REVIEW_REQUIRED on extraction, EXPORT_BLOCKED on export).
"""
