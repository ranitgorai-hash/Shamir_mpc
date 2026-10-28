"""Run protocols with every party in its own OS process, over TCP on localhost."""

from __future__ import annotations

import asyncio
import multiprocessing
import queue
import socket
from dataclasses import dataclass
from typing import Sequence

from .bgw import run_circuit_party
from .circuit import Circuit
from .field import PrimeField
from .party import run_party
from .shamir import DEFAULT_FIELD


@dataclass
class SecureSumRun:
    n: int
    t: int
    totals: list[int]               # total as computed by each party
    wire_logs: list[list[dict]]     # per party: {"dir","peer","raw"} entries

    def messages(self, direction: str = "out") -> list[dict]:
        return [m for log in self.wire_logs for m in log if m["dir"] == direction]

    @property
    def message_count(self) -> int:
        return len(self.messages("out"))


@dataclass
class CircuitRun:
    n: int
    t: int
    circuit: Circuit
    inputs: list[list[int]]          # kept by the test harness only; parties never see each other's
    outputs: list[list[int]]         # outputs as computed by each party
    wire_shares: list[dict]          # per party: wire -> that party's share
    wire_logs: list[list[dict]]

    def messages(self, direction: str = "out") -> list[dict]:
        return [m for log in self.wire_logs for m in log if m["dir"] == direction]

    @property
    def message_count(self) -> int:
        return len(self.messages("out"))

    @property
    def result(self) -> list[int]:
        if any(o != self.outputs[0] for o in self.outputs):
            raise RuntimeError("parties disagree on the output")
        return self.outputs[0]


def free_ports(n: int, host: str = "127.0.0.1") -> list[int]:
    socks = [socket.socket() for _ in range(n)]
    try:
        for s in socks:
            s.bind((host, 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _party_main(index, n, t, x, host, ports, prime, timeout, results) -> None:
    try:
        res = asyncio.run(run_party(index, n, t, x, host, ports, PrimeField(prime), timeout))
        results.put({"ok": True, "index": index, "total": str(res.total), "wire_log": res.wire_log})
    except BaseException as exc:  # report any failure to the parent instead of hanging it
        results.put({"ok": False, "index": index, "error": repr(exc)})


def _circuit_party_main(index, n, t, circuit, my_inputs, host, ports, prime, timeout, results) -> None:
    try:
        res = asyncio.run(
            run_circuit_party(index, n, t, circuit, my_inputs, host, ports, PrimeField(prime), timeout)
        )
        results.put({"ok": True, "index": index, "outputs": res.outputs,
                     "wire_shares": res.wire_shares, "wire_log": res.wire_log})
    except BaseException as exc:
        results.put({"ok": False, "index": index, "error": repr(exc)})


def _spawn_and_collect(target, per_party_args: list[tuple], timeout: float) -> list[dict]:
    """Start one process per party (args get ``results`` appended) and gather replies."""
    n = len(per_party_args)
    ctx = multiprocessing.get_context("spawn")  # same behaviour on Linux/macOS/Windows
    results = ctx.Queue()
    procs = [ctx.Process(target=target, args=(*a, results)) for a in per_party_args]
    for p in procs:
        p.start()
    try:
        collected = {}
        for _ in range(n):
            try:
                item = results.get(timeout=timeout + 15)
            except queue.Empty:
                raise RuntimeError("timed out waiting for parties to finish") from None
            if not item["ok"]:
                raise RuntimeError(f"party {item['index']} failed: {item['error']}")
            collected[item["index"]] = item
        for p in procs:
            p.join(timeout=10)
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
    return [collected[i] for i in range(n)]


def run_secure_sum(
    inputs: Sequence[int],
    t: int,
    *,
    field: PrimeField = DEFAULT_FIELD,
    host: str = "127.0.0.1",
    timeout: float = 30.0,
) -> SecureSumRun:
    """Compute sum(inputs) mod p with one process per party (Phase 2 protocol)."""
    n = len(inputs)
    if n < 2:
        raise ValueError("need at least 2 parties")
    if not 1 <= t <= n:
        raise ValueError("need 1 <= t <= n")
    if not all(field.contains(x) for x in inputs):
        raise ValueError("every input must be an integer in [0, p)")
    ports = free_ports(n, host)
    rows = _spawn_and_collect(
        _party_main, [(i, n, t, inputs[i], host, ports, field.p, timeout) for i in range(n)], timeout
    )
    return SecureSumRun(n, t, [int(r["total"]) for r in rows], [r["wire_log"] for r in rows])


def run_circuit(
    circuit: Circuit,
    inputs: Sequence[Sequence[int]],
    t: int,
    *,
    field: PrimeField = DEFAULT_FIELD,
    host: str = "127.0.0.1",
    timeout: float = 30.0,
) -> CircuitRun:
    """Evaluate ``circuit`` with BGW-style MPC, one process per party (Phase 3)."""
    n = circuit.n_parties
    if len(inputs) != n:
        raise ValueError("need one list of inputs per party")
    if not 1 <= t <= n or n < circuit.min_parties(t):
        raise ValueError(f"this circuit needs n >= {circuit.min_parties(t)} parties for t={t} (n={n})")
    for i in range(n):
        if len(inputs[i]) < circuit.slots(i) or not all(field.contains(v) for v in inputs[i]):
            raise ValueError(f"party {i}: missing or out-of-range inputs")
    ports = free_ports(n, host)
    rows = _spawn_and_collect(
        _circuit_party_main,
        [(i, n, t, circuit, list(inputs[i]), host, ports, field.p, timeout) for i in range(n)],
        timeout,
    )
    return CircuitRun(
        n, t, circuit, [list(v) for v in inputs],
        [r["outputs"] for r in rows], [r["wire_shares"] for r in rows], [r["wire_log"] for r in rows],
    )
