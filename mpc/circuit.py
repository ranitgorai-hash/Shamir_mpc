"""Arithmetic circuits over GF(p): a builder, a plaintext reference evaluator,
and ready-made circuits (sum, dot product, variance numerator).

Gate kinds: input (party, slot), const, add, sub, cmul (multiply by a public
constant) and mul (the only gate that needs interaction).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .field import PrimeField
from .shamir import DEFAULT_FIELD


@dataclass(frozen=True)
class Gate:
    op: str          # "input" | "const" | "add" | "sub" | "cmul" | "mul"
    args: tuple = ()  # input: (party, slot); const: (c,); add/sub/mul: (w1, w2); cmul: (w, c)


class Circuit:
    def __init__(self, n_parties: int) -> None:
        if n_parties < 2:
            raise ValueError("need at least 2 parties")
        self.n_parties = n_parties
        self.gates: list[Gate] = []
        self.outputs: list[int] = []

    def _wire(self, w: int) -> int:
        if not (isinstance(w, int) and 0 <= w < len(self.gates)):
            raise ValueError(f"unknown wire {w}")
        return w

    def _add(self, op: str, *args) -> int:
        self.gates.append(Gate(op, args))
        return len(self.gates) - 1

    def input(self, party: int, slot: int = 0) -> int:
        if not 0 <= party < self.n_parties or slot < 0:
            raise ValueError("bad party or slot")
        return self._add("input", party, slot)

    def const(self, c: int) -> int:
        return self._add("const", c)

    def add(self, a: int, b: int) -> int:
        return self._add("add", self._wire(a), self._wire(b))

    def sub(self, a: int, b: int) -> int:
        return self._add("sub", self._wire(a), self._wire(b))

    def cmul(self, a: int, c: int) -> int:
        return self._add("cmul", self._wire(a), c)

    def mul(self, a: int, b: int) -> int:
        return self._add("mul", self._wire(a), self._wire(b))

    def output(self, w: int) -> int:
        self.outputs.append(self._wire(w))
        return w

    @property
    def mul_gates(self) -> list[int]:
        return [w for w, g in enumerate(self.gates) if g.op == "mul"]

    def slots(self, party: int) -> int:
        """How many private values ``party`` must supply."""
        used = [g.args[1] for g in self.gates if g.op == "input" and g.args[0] == party]
        return max(used) + 1 if used else 0

    def min_parties(self, t: int) -> int:
        """Multiplying two degree t-1 sharings gives degree 2t-2, which needs
        2t-1 points to reconstruct; circuits without mul gates only need t."""
        return 2 * t - 1 if self.mul_gates else t


def evaluate_wires(circuit: Circuit, inputs: Sequence[Sequence[int]], field: PrimeField = DEFAULT_FIELD) -> list[int]:
    """Plaintext value of every wire (reference for the MPC, used in tests)."""
    vals: list[int] = []
    for g in circuit.gates:
        a = g.args
        if g.op == "input":
            v = inputs[a[0]][a[1]]
        elif g.op == "const":
            v = a[0]
        elif g.op == "add":
            v = vals[a[0]] + vals[a[1]]
        elif g.op == "sub":
            v = vals[a[0]] - vals[a[1]]
        elif g.op == "cmul":
            v = vals[a[0]] * a[1]
        else:
            v = vals[a[0]] * vals[a[1]]
        vals.append(field.reduce(v))
    return vals


def evaluate_plain(circuit: Circuit, inputs: Sequence[Sequence[int]], field: PrimeField = DEFAULT_FIELD) -> list[int]:
    """Reference evaluation on the plaintext inputs, used to check the MPC."""
    vals = evaluate_wires(circuit, inputs, field)
    return [vals[w] for w in circuit.outputs]


# --- Ready-made circuits ------------------------------------------------------

def sum_circuit(n: int) -> Circuit:
    c = Circuit(n)
    acc = c.input(0)
    for i in range(1, n):
        acc = c.add(acc, c.input(i))
    c.output(acc)
    return c


def dot_product_circuit(n: int) -> Circuit:
    """Party i holds (a_i, b_i) in slots 0 and 1; output = sum a_i * b_i."""
    c = Circuit(n)
    acc = None
    for i in range(n):
        prod = c.mul(c.input(i, 0), c.input(i, 1))
        acc = prod if acc is None else c.add(acc, prod)
    c.output(acc)
    return c


def variance_circuit(n: int) -> Circuit:
    """Party i holds x_i. Output = n * sum(x^2) - (sum x)^2 = n^2 * Var(x)."""
    c = Circuit(n)
    xs = [c.input(i) for i in range(n)]
    s1 = xs[0]
    s2 = c.mul(xs[0], xs[0])
    for x in xs[1:]:
        s1 = c.add(s1, x)
        s2 = c.add(s2, c.mul(x, x))
    c.output(c.sub(c.cmul(s2, n), c.mul(s1, s1)))
    return c
