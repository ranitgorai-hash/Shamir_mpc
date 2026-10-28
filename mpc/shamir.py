"""Shamir (t, n) threshold secret sharing over a prime field.

A secret s is hidden as f(0) of a random polynomial of degree t-1 whose other
coefficients are uniform in GF(p). Party i receives the share (i, f(i)).
Any t shares recover s by Lagrange interpolation at x = 0; any t-1 shares are
consistent with every possible secret (information-theoretic privacy).

Educational code: semi-honest model only, no protection against malicious
share holders and no side-channel hardening.
"""

from __future__ import annotations

from typing import NamedTuple, Sequence

from .field import DEFAULT_PRIME, PrimeField

DEFAULT_FIELD = PrimeField(DEFAULT_PRIME)


class Share(NamedTuple):
    """A point (x, y) on the sharing polynomial. x is the party index (>= 1)."""

    x: int
    y: int


def evaluate_polynomial(coeffs: Sequence[int], x: int, field: PrimeField) -> int:
    """Evaluate coeffs[0] + coeffs[1]*x + ... using Horner's rule."""
    result = 0
    for c in reversed(coeffs):
        result = field.add(field.mul(result, x), c)
    return result


def split(
    secret: int,
    t: int,
    n: int,
    field: PrimeField = DEFAULT_FIELD,
) -> list[Share]:
    """Split ``secret`` into ``n`` shares, any ``t`` of which reconstruct it."""
    if not field.contains(secret):
        raise ValueError("secret must be an integer in [0, p)")
    if not 1 <= t <= n:
        raise ValueError("need 1 <= t <= n")
    if n >= field.p:
        raise ValueError("n must be smaller than the field modulus")
    coeffs = [secret] + [field.random_element() for _ in range(t - 1)]
    return [Share(i, evaluate_polynomial(coeffs, i, field)) for i in range(1, n + 1)]


def lagrange_coefficients_at_zero(xs: Sequence[int], field: PrimeField) -> list[int]:
    """Weights w_i such that f(0) = sum(w_i * f(x_i)) for any polynomial of
    degree < len(xs). Reused later for secure multiplication."""
    if len(set(xs)) != len(xs):
        raise ValueError("share x-coordinates must be distinct")
    if any(x % field.p == 0 for x in xs):
        raise ValueError("x = 0 is reserved for the secret")
    weights = []
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i != j:
                num = field.mul(num, field.neg(xj))
                den = field.mul(den, field.sub(xi, xj))
        weights.append(field.div(num, den))
    return weights


def reconstruct(shares: Sequence[Share], field: PrimeField = DEFAULT_FIELD) -> int:
    """Recover the secret from shares via Lagrange interpolation at x = 0.

    The threshold t is not stored in the shares: with fewer than t shares this
    still returns a value, but it is unrelated to the real secret.
    """
    if not shares:
        raise ValueError("need at least one share")
    xs = [s.x for s in shares]
    weights = lagrange_coefficients_at_zero(xs, field)
    secret = 0
    for w, s in zip(weights, shares):
        secret = field.add(secret, field.mul(w, s.y))
    return secret


# --- Linear homomorphism: operate on shares without reconstructing -----------

def add_shares(a: Share, b: Share, field: PrimeField = DEFAULT_FIELD) -> Share:
    """Share of (secret_a + secret_b), from two shares held by the same party."""
    if a.x != b.x:
        raise ValueError("shares must belong to the same party (same x)")
    return Share(a.x, field.add(a.y, b.y))


def scale_share(a: Share, k: int, field: PrimeField = DEFAULT_FIELD) -> Share:
    """Share of (k * secret) from a share of the secret."""
    return Share(a.x, field.mul(a.y, k))


# --- Interpolation at any point, and consistency-checked reconstruction -------

def interpolate_at(shares: Sequence[Share], x0: int, field: PrimeField = DEFAULT_FIELD) -> int:
    """Value at ``x0`` of the unique polynomial of degree < len(shares) through
    the given points (Lagrange interpolation). ``x0 = 0`` gives the secret."""
    xs = [s.x for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("share x-coordinates must be distinct")
    total = 0
    for i, si in enumerate(shares):
        num, den = 1, 1
        for j, sj in enumerate(shares):
            if i != j:
                num = field.mul(num, field.sub(x0, sj.x))
                den = field.mul(den, field.sub(si.x, sj.x))
        total = field.add(total, field.mul(si.y, field.div(num, den)))
    return total


def reconstruct_checked(shares: Sequence[Share], t: int, field: PrimeField = DEFAULT_FIELD) -> int:
    """Reconstruct from the first ``t`` shares and verify every extra share lies
    on the same degree t-1 polynomial. Detects faulty or tampered shares (it is
    error *detection* for honest-but-buggy parties, not security against a
    malicious adversary)."""
    if len(shares) < t:
        raise ValueError("need at least t shares")
    base = list(shares[:t])
    for extra in shares[t:]:
        if interpolate_at(base, extra.x, field) != extra.y:
            raise ValueError(f"inconsistent share at x={extra.x}: not on the degree-{t - 1} polynomial")
    return reconstruct(base, field)
