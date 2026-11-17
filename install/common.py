"""Shared fail-closed primitives; no side effects."""
import hashlib


class Refusal(RuntimeError):
    """A deliberately closed safety gate (messages contain no input values)."""


def need(condition, label):
    if not condition:
        raise Refusal(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()
