"""High-level secure computations built on the circuit engine.

Each helper returns (value, run). The revealed field element is turned into the
final number with public arithmetic. Results must stay below p; the helpers
check this on the harness side, since a real deployment would agree on input
bounds in advance.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Sequence

from .circuit import dot_product_circuit, sum_circuit, variance_circuit
from .runner import CircuitRun, run_circuit
from .shamir import DEFAULT_FIELD


def _no_wrap(bound: int, what: str) -> None:
    if bound >= DEFAULT_FIELD.p:
        raise ValueError(f"inputs too large: {what} would wrap around modulo p")


def secure_average(inputs: Sequence[int], t: int, **kw) -> tuple[Fraction, CircuitRun]:
    """Average of the parties' inputs; only the sum is revealed, then divided by n."""
    n = len(inputs)
    _no_wrap(sum(inputs), "the sum")
    run = run_circuit(sum_circuit(n), [[x] for x in inputs], t, **kw)
    return Fraction(run.result[0], n), run


def secure_dot_product(a: Sequence[int], b: Sequence[int], t: int, **kw) -> tuple[int, CircuitRun]:
    """Party i holds (a_i, b_i); the output is sum a_i * b_i. Needs n >= 2t-1."""
    if len(a) != len(b):
        raise ValueError("vectors must have the same length")
    _no_wrap(sum(x * y for x, y in zip(a, b)), "the dot product")
    run = run_circuit(dot_product_circuit(len(a)), [[x, y] for x, y in zip(a, b)], t, **kw)
    return run.result[0], run


def secure_variance(inputs: Sequence[int], t: int, **kw) -> tuple[Fraction, CircuitRun]:
    """Population variance. The parties reveal only n*sum(x^2) - (sum x)^2, i.e.
    n^2 * Var, never the mean or the sum separately. Needs n >= 2t-1."""
    n = len(inputs)
    _no_wrap(n * sum(x * x for x in inputs), "n * sum of squares")
    run = run_circuit(variance_circuit(n), [[x] for x in inputs], t, **kw)
    return Fraction(run.result[0], n * n), run
