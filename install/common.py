"""Shared fail-closed primitives; no side effects."""
import hashlib


class Refusal(RuntimeError):
    """A deliberately closed safety gate (messages contain no input values)."""


class ObservationUnavailable(Refusal):
    """No usable read response; not a schema, identity or policy rejection.

    Only explicitly scoped read-only callers may elect to retry this category.
    """


def need(condition, label):
    if not condition:
        raise Refusal(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()
