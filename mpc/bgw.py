"""BGW-style evaluation of an arithmetic circuit on secret-shared values.

Every wire value is Shamir-shared with a degree t-1 polynomial (any t shares
reconstruct, t-1 reveal nothing). Gate by gate:

  input   the owner shares its value and sends share j to party j.
  add/sub/cmul/const   each party works on its own shares: no communication.
  mul     each party multiplies its two shares locally. That is a point on a
          polynomial of degree 2t-2 whose constant term is the product, so
          2t-1 points determine it. Degree reduction: each party re-shares its
          local product with a fresh degree t-1 polynomial g_j; the new share of
          party i is sum_j lambda_j * g_j(i) with lambda the Lagrange weights at 0
          for x = 1..n. That is a fresh, uniformly random degree t-1 sharing of
          the product. Needs n >= 2t-1.
  output  each party sends its share of the output wire to all others, and every
          party interpolates (with a consistency check on the extra shares).

Semi-honest model, private channels; see net.py for the TLS caveat.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field as dc_field
from typing import Sequence

from .circuit import Circuit
from .field import PrimeField
from .net import connect_with_retry, read_msg, send_msg
from .shamir import (
    DEFAULT_FIELD, Share, lagrange_coefficients_at_zero, reconstruct_checked, split,
)


@dataclass
class CircuitPartyResult:
    index: int
    outputs: list[int]
    wire_shares: dict[int, int]  # this party's share (y) of every wire
    wire_log: list[dict] = dc_field(default_factory=list)  # {"dir","peer","raw"}


class Inbox:
    """Messages received so far, keyed by (kind, gate) and then by sender."""

    def __init__(self) -> None:
        self._data: dict = defaultdict(dict)
        self._cv = asyncio.Condition()

    async def put(self, kind: str, gate: int, sender: int, share: Share) -> None:
        async with self._cv:
            self._data[(kind, gate)].setdefault(sender, share)
            self._cv.notify_all()

    async def collect(self, kind: str, gate: int, count: int, timeout: float) -> dict[int, Share]:
        async with self._cv:
            await asyncio.wait_for(
                self._cv.wait_for(lambda: len(self._data[(kind, gate)]) >= count), timeout
            )
            return dict(self._data[(kind, gate)])


def _acceptable(circuit: Circuit, n: int, index: int, kind: str, sender: int, gate: int, share: Share) -> bool:
    """Accept only messages that make sense for this circuit; drop the rest."""
    if not (0 <= sender < n and sender != index and 0 <= gate < len(circuit.gates)):
        return False
    g = circuit.gates[gate]
    if kind == "in":
        return g.op == "input" and g.args[0] == sender and share.x == index + 1
    if kind == "mul":
        return g.op == "mul" and share.x == index + 1
    if kind == "open":
        return gate in circuit.outputs and share.x == sender + 1
    return False


async def run_circuit_party(
    index: int,
    n: int,
    t: int,
    circuit: Circuit,
    my_inputs: Sequence[int],
    host: str,
    ports: Sequence[int],
    field: PrimeField = DEFAULT_FIELD,
    timeout: float = 30.0,
) -> CircuitPartyResult:
    if n < 2 or len(ports) != n or not 0 <= index < n or n != circuit.n_parties:
        raise ValueError("inconsistent n / ports / index / circuit")
    if not 1 <= t <= n or n < circuit.min_parties(t):
        raise ValueError(f"this circuit needs n >= {circuit.min_parties(t)} parties for t={t}")
    if len(my_inputs) < circuit.slots(index) or not all(field.contains(v) for v in my_inputs):
        raise ValueError("missing or out-of-range private inputs")

    wire_log: list[dict] = []
    inbox = Inbox()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                try:
                    msg, raw = await read_msg(reader)
                except (asyncio.IncompleteReadError, ConnectionError, ValueError):
                    return
                try:
                    kind, sender, gate = msg["type"], int(msg["from"]), int(msg["gate"])
                    share = Share(int(msg["x"]), int(msg["y"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if _acceptable(circuit, n, index, kind, sender, gate, share):
                    wire_log.append({"dir": "in", "peer": sender, "raw": raw.decode()})
                    await inbox.put(kind, gate, sender, share)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host, ports[index])
    writers: dict[int, asyncio.StreamWriter] = {}
    try:
        peers = [j for j in range(n) if j != index]
        conns = await asyncio.gather(*(connect_with_retry(host, ports[j], timeout) for j in peers))
        for j, (_, w) in zip(peers, conns):
            writers[j] = w

        async def send(j: int, kind: str, gate: int, share: Share) -> None:
            raw = await send_msg(
                writers[j],
                {"type": kind, "from": index, "gate": gate, "x": share.x, "y": str(share.y)},
            )
            wire_log.append({"dir": "out", "peer": j, "raw": raw.decode()})

        values: dict[int, int] = {}  # wire -> my share of it

        # Input stage: share my own inputs, then collect everyone else's.
        for w, g in enumerate(circuit.gates):
            if g.op == "input" and g.args[0] == index:
                shares = split(my_inputs[g.args[1]], t, n, field)
                values[w] = shares[index].y
                for j in peers:
                    await send(j, "in", w, shares[j])
        for w, g in enumerate(circuit.gates):
            if g.op == "input" and g.args[0] != index:
                got = await inbox.collect("in", w, 1, timeout)
                values[w] = got[g.args[0]].y

        # Computation stage.
        lam = lagrange_coefficients_at_zero(list(range(1, n + 1)), field) if circuit.mul_gates else []
        for w, g in enumerate(circuit.gates):
            a = g.args
            if g.op == "const":
                values[w] = field.reduce(a[0])  # a constant is a degree-0 sharing
            elif g.op == "add":
                values[w] = field.add(values[a[0]], values[a[1]])
            elif g.op == "sub":
                values[w] = field.sub(values[a[0]], values[a[1]])
            elif g.op == "cmul":
                values[w] = field.mul(values[a[0]], a[1])
            elif g.op == "mul":
                local = field.mul(values[a[0]], values[a[1]])  # point on a degree 2t-2 polynomial
                sub = split(local, t, n, field)                # re-share with a fresh degree t-1 polynomial
                for j in peers:
                    await send(j, "mul", w, sub[j])
                got = await inbox.collect("mul", w, n - 1, timeout)
                acc = field.mul(lam[index], sub[index].y)
                for j, s in got.items():
                    acc = field.add(acc, field.mul(lam[j], s.y))
                values[w] = acc

        # Output stage: open the output wires.
        outs = list(dict.fromkeys(circuit.outputs))
        for w in outs:
            for j in peers:
                await send(j, "open", w, Share(index + 1, values[w]))
        opened: dict[int, int] = {}
        for w in outs:
            got = await inbox.collect("open", w, n - 1, timeout)
            pts = [Share(index + 1, values[w]), *got.values()]
            opened[w] = reconstruct_checked(pts, t, field)
        return CircuitPartyResult(index, [opened[w] for w in circuit.outputs], values, wire_log)
    finally:
        for w in writers.values():
            w.close()
        server.close()
