"""One party of the secure-sum protocol (semi-honest model, private channels).

Protocol, for n parties with inputs x_0..x_{n-1} and threshold t:

  Round 1 (share):   party i splits x_i into n Shamir shares and sends share j
                     (the point with x-coordinate j+1) privately to party j.
  Local step:        party j adds the n shares it now holds, one per input.
                     By linearity this is a share of x_0 + ... + x_{n-1}.
  Round 2 (reveal):  every party sends its summed share to all others, and
                     each party interpolates the total from the n summed shares.

Only the total is ever reconstructed. Individual inputs are never sent in the
clear, and any t-1 colluding parties see shares that are independent of them.
Every message sent or received is appended to ``wire_log`` so tests and the
dashboard can audit exactly what crossed the network.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field as dc_field
from typing import Sequence

from .field import PrimeField
from .net import connect_with_retry, read_msg, send_msg
from .shamir import DEFAULT_FIELD, Share, add_shares, reconstruct, split


@dataclass
class PartyResult:
    index: int
    total: int
    wire_log: list[dict] = dc_field(default_factory=list)  # {"dir","peer","raw"}


async def run_party(
    index: int,
    n: int,
    t: int,
    x: int,
    host: str,
    ports: Sequence[int],
    field: PrimeField = DEFAULT_FIELD,
    timeout: float = 30.0,
) -> PartyResult:
    """Run party ``index`` to completion and return the agreed total."""
    if n < 2 or len(ports) != n or not 0 <= index < n:
        raise ValueError("need n >= 2, one port per party, and 0 <= index < n")
    if not field.contains(x):
        raise ValueError("input must be an integer in [0, p)")

    wire_log: list[dict] = []
    shares_in: dict[int, Share] = {}
    sums_in: dict[int, Share] = {}
    got_shares, got_sums = asyncio.Event(), asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                try:
                    msg, raw = await read_msg(reader)
                except (asyncio.IncompleteReadError, ConnectionError, ValueError):
                    return  # peer closed, or sent garbage: drop the connection
                try:
                    kind, sender = msg["type"], int(msg["from"])
                    share = Share(int(msg["x"]), int(msg["y"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if not 0 <= sender < n or sender == index:
                    continue
                wire_log.append({"dir": "in", "peer": sender, "raw": raw.decode()})
                if kind == "share" and share.x == index + 1 and sender not in shares_in:
                    shares_in[sender] = share
                    if len(shares_in) == n - 1:
                        got_shares.set()
                elif kind == "sum" and share.x == sender + 1 and sender not in sums_in:
                    sums_in[sender] = share
                    if len(sums_in) == n - 1:
                        got_sums.set()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host, ports[index])
    writers: dict[int, asyncio.StreamWriter] = {}
    try:
        peers = [j for j in range(n) if j != index]
        conns = await asyncio.gather(
            *(connect_with_retry(host, ports[j], timeout) for j in peers)
        )
        for j, (_, w) in zip(peers, conns):
            writers[j] = w

        async def send(j: int, kind: str, share: Share) -> None:
            raw = await send_msg(
                writers[j],
                {"type": kind, "from": index, "x": share.x, "y": str(share.y)},
            )
            wire_log.append({"dir": "out", "peer": j, "raw": raw.decode()})

        # Round 1: share my input, keep my own share, send the others theirs.
        my_shares = split(x, t, n, field)
        for j in peers:
            await send(j, "share", my_shares[j])
        await asyncio.wait_for(got_shares.wait(), timeout)

        # Local step: add the n shares I hold (one per party's input).
        summed = my_shares[index]
        for s in shares_in.values():
            summed = add_shares(summed, s, field)

        # Round 2: reveal my summed share; interpolate the total.
        for j in peers:
            await send(j, "sum", summed)
        await asyncio.wait_for(got_sums.wait(), timeout)
        total = reconstruct([summed, *sums_in.values()], field)
        return PartyResult(index, total, wire_log)
    finally:
        for w in writers.values():
            w.close()
        server.close()
