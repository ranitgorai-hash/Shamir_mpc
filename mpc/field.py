"""Prime-field arithmetic GF(p) used by the secret-sharing code.

Educational implementation. Python's built-in big integers give us exact
arithmetic, and ``pow(a, -1, p)`` gives modular inverses.
"""

from __future__ import annotations

import secrets

# 2**127 - 1 is a Mersenne prime, large enough to hold 126-bit secrets.
DEFAULT_PRIME = 2**127 - 1

_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin primality test with the first 12 primes as fixed bases.
    Provably deterministic for n < 3.18e23; above that (including the default
    2**127 - 1) it is a probabilistic test with negligible error in practice."""
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class PrimeField:
    """The finite field of integers modulo a prime ``p``."""

    def __init__(self, p: int = DEFAULT_PRIME) -> None:
        if not is_probable_prime(p):
            raise ValueError(f"modulus {p} is not prime")
        self.p = p

    def __repr__(self) -> str:
        return f"PrimeField({self.p})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PrimeField) and self.p == other.p

    def __hash__(self) -> int:
        return hash(self.p)

    def reduce(self, a: int) -> int:
        return a % self.p

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p

    def neg(self, a: int) -> int:
        return (-a) % self.p

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        a %= self.p
        if a == 0:
            raise ZeroDivisionError("0 has no multiplicative inverse")
        return pow(a, -1, self.p)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def pow(self, a: int, e: int) -> int:
        return pow(a % self.p, e, self.p)

    def random_element(self) -> int:
        """Uniform element of the field from a cryptographically secure RNG."""
        return secrets.randbelow(self.p)

    def contains(self, a: int) -> bool:
        return isinstance(a, int) and 0 <= a < self.p
