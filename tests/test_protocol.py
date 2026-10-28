"""Phase 2 tests: secure sum over real TCP sockets, one OS process per party."""

import asyncio
import json
import random
import struct
from collections import Counter

import pytest

from mpc import DEFAULT_PRIME, Share, free_ports, reconstruct, run_party, run_secure_sum
from mpc.net import MAX_MESSAGE, encode_msg, read_msg

P = DEFAULT_PRIME
INPUTS = [random.Random(2026).randrange(10**17, 10**18) for _ in range(5)]
N, T = 5, 3


@pytest.fixture(scope="module")
def run5():
    """One shared 5-party, t=3 run; several tests audit its wire logs."""
    return run_secure_sum(INPUTS, t=T)


def _shares_seen_by(run, party, victim):
    """Shares of `victim`'s input that `party` received on the wire."""
    out = []
    for m in run.wire_logs[party]:
        obj = json.loads(m["raw"])
        if m["dir"] == "in" and obj["type"] == "share" and obj["from"] == victim:
            out.append(Share(obj["x"], int(obj["y"])))
    return out


# --- Correctness --------------------------------------------------------------

def test_every_party_computes_the_correct_total(run5):
    assert run5.totals == [sum(INPUTS) % P] * N


def test_three_party_example():
    assert run_secure_sum([10, 20, 30], t=2).totals == [60, 60, 60]


def test_sum_wraps_modulo_p():
    assert run_secure_sum([P - 1, 5, 7], t=2).totals == [11, 11, 11]


# --- Communication pattern ----------------------------------------------------

def test_message_counts(run5):
    # Round 1: n(n-1) share messages; round 2: n(n-1) summed-share messages.
    assert run5.message_count == 2 * N * (N - 1)
    assert len(run5.messages("in")) == 2 * N * (N - 1)
    assert all(
        sum(1 for m in log if m["dir"] == "out") == 2 * (N - 1) for log in run5.wire_logs
    )


def test_every_sent_message_is_received_exactly_once(run5):
    sent = Counter(
        (i, m["peer"], m["raw"])
        for i, log in enumerate(run5.wire_logs) for m in log if m["dir"] == "out"
    )
    received = Counter(
        (m["peer"], i, m["raw"])
        for i, log in enumerate(run5.wire_logs) for m in log if m["dir"] == "in"
    )
    assert sent == received


# --- Privacy ------------------------------------------------------------------

def test_no_private_input_ever_appears_on_the_wire(run5):
    for m in run5.messages("out") + run5.messages("in"):
        obj = json.loads(m["raw"])
        assert set(obj) == {"type", "from", "x", "y"}
        assert obj["type"] in {"share", "sum"}
        assert int(obj["y"]) not in INPUTS
        for x in INPUTS:
            assert str(x) not in m["raw"]


def test_t_minus_1_colluding_parties_cannot_recover_an_input(run5):
    victim = N - 1
    coalition = list(range(T - 1))  # t - 1 = 2 colluding parties
    seen = [s for p in coalition for s in _shares_seen_by(run5, p, victim)]
    assert len(seen) == T - 1
    assert reconstruct(seen) != INPUTS[victim]


def test_t_colluding_parties_can_recover_an_input(run5):
    """The flip side: the threshold is exactly t, so t colluders do win."""
    victim = N - 1
    seen = [s for p in range(T) for s in _shares_seen_by(run5, p, victim)]
    assert len(seen) == T
    assert reconstruct(seen) == INPUTS[victim]


# --- Input validation and failure handling -----------------------------------

@pytest.mark.parametrize("inputs,t", [
    ([5], 1), ([1, 2, 3], 4), ([1, 2, 3], 0), ([1, -2, 3], 2), ([1, P, 3], 2),
])
def test_run_secure_sum_rejects_bad_parameters(inputs, t):
    with pytest.raises(ValueError):
        run_secure_sum(inputs, t)


def test_party_fails_cleanly_when_peers_never_start():
    ports = free_ports(2)
    with pytest.raises((OSError, TimeoutError)):
        asyncio.run(run_party(0, 2, 2, 5, "127.0.0.1", ports, timeout=0.5))


# --- Framing ------------------------------------------------------------------

def _reader_with(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def test_framing_roundtrip():
    msg = {"type": "share", "from": 1, "x": 2, "y": "12345"}
    raw = encode_msg(msg)

    async def go():
        return await read_msg(_reader_with(struct.pack(">I", len(raw)) + raw))

    parsed, got_raw = asyncio.run(go())
    assert parsed == msg and got_raw == raw


def test_framing_rejects_oversized_truncated_and_non_object_frames():
    async def read(data):
        return await read_msg(_reader_with(data))

    with pytest.raises(ValueError):
        asyncio.run(read(struct.pack(">I", MAX_MESSAGE + 1)))
    with pytest.raises(asyncio.IncompleteReadError):
        asyncio.run(read(struct.pack(">I", 50) + b"short"))
    with pytest.raises(ValueError):
        asyncio.run(read(struct.pack(">I", 2) + b"[]"))
