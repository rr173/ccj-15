"""Deterministic weighted target selection.

Uses weighted rendezvous hashing (HRW, exponential-race form). The ranking
is a pure function of (selection key, target ids, weights), so every node
holding the same config version and the same view of target health ranks
targets identically. Failover within a config version is therefore a
deterministic walk down the ranking, and recovery deterministically flips
back -- nodes cannot diverge permanently.
"""
from __future__ import annotations

import hashlib
import math

from .models import Target


def _unit_interval(seed: str) -> float:
    h = hashlib.blake2b(seed.encode("utf-8"), digest_size=8).digest()
    n = int.from_bytes(h, "big")
    return (n + 1) / (1 << 64)  # (0, 1]


def rank_targets(key: str, targets: list[Target]) -> list[Target]:
    """Return targets ordered by deterministic weighted preference.

    P(target first) is proportional to its weight. Weight-0 targets rank
    last (they are only used when nothing else exists). Ties break on
    target id so the order is total and stable.
    """
    scored = []
    for t in targets:
        if t.weight > 0:
            u = _unit_interval(f"{key}#{t.id}")
            score = -math.log(u) / t.weight  # exponential race: pick minimum
        else:
            score = float("inf")
        scored.append((score, t.id, t))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [t for _, _, t in scored]


def gray_bucket(seed: str) -> int:
    """Deterministic bucket in 0..99 for a seed.

    The seed mixes the config version, the release-group fingerprint
    (window, labels, percent, targets) and the client key, so a client is
    stable while nothing changes and is reshuffled the moment any of the
    inputs move.
    """
    return min(99, int(_unit_interval(seed) * 100))
