"""Phase 3 tests: circuit evaluation, degree reduction, secure average / dot product / variance."""

import json
import random
import statistics
from fractions import Fraction

import pytest

from mpc import (
    Circuit, DEFAULT_FIELD, DEFAULT_PRIME, Share, dot_product_circuit, evaluate_plain, evaluate_polynomial,
    evaluate_wires, interpolate_at, lagrange_coefficients_at_zero, reconstruct, reconstruct_checked,
    run_circuit, secure_average, secure_dot_product, secure_variance, split, sum_circuit, variance_circuit,
)

P = DEFAULT_PRIME
F = DEFAULT_FIELD


# --- Interpolation helpers ----------------------------------------------------

def test_interpolate_at_matches_the_polynomial():
    coeffs = [5, 7, 11]
    pts = [Share(x, evaluate_polynomial(coeffs, x, F)) for x in (1, 2, 3)]
    assert interpolate_at(pts, 10) == evaluate_polynomial(coeffs, 10, F)
    assert interpolate_at(pts, 0) == 5 == reconstruct(pts)


def test_reconstruct_checked_accepts_consistent_shares():
    assert reconstruct_checked(split(99, 3, 6), 3) == 99


@pytest.mark.parametrize("position", [0, 4])
def test_reconstruct_checked_detects_a_tampered_share(position):
    shares = split(99, 3, 6)
    shares[position] = Share(shares[position].x, (shares[position].y + 1) % P)
    with pytest.raises(ValueError):
        reconstruct_checked(shares, 3)


def test_reconstruct_checked_needs_t_shares():
    with pytest.raises(ValueError):
        reconstruct_checked(split(99, 3, 6)[:2], 3)


# --- Circuit builder and plaintext reference -----------------------------------

def test_plain_reference_circuits():
    assert evaluate_plain(sum_circuit(4), [[1], [2], [3], [4]]) == [10]
    assert evaluate_plain(dot_product_circuit(3), [[1, 4], [2, 5], [3, 6]]) == [32]
    xs = [12, 7, 30, 21, 9]
    assert evaluate_plain(variance_circuit(5), [[x] for x in xs]) == [5 * sum(x * x for x in xs) - sum(xs) ** 2]


def test_constants_and_wraparound_in_the_reference():
    c = Circuit(2)
    c.output(c.cmul(c.input(0), 2))
    assert evaluate_plain(c, [[P - 1], []]) == [P - 2]


def test_builder_rejects_bad_wires_and_parties():
    with pytest.raises(ValueError):
        Circuit(1)
    with pytest.raises(ValueError):
        Circuit(3).add(0, 1)
    with pytest.raises(ValueError):
        Circuit(3).input(5)


def test_slots_and_minimum_parties():
    assert dot_product_circuit(3).slots(0) == 2
    assert dot_product_circuit(3).min_parties(2) == 3      # 2t - 1
    assert sum_circuit(4).min_parties(3) == 3              # no mul gate: just t


# --- Degree reduction, without the network ---------------------------------------

A, B = 123456789, 987654321


def _local_products(n, t):
    fa, fb = split(A, t, n), split(B, t, n)
    return [Share(x.x, x.y * y.y % P) for x, y in zip(fa, fb)]


def test_local_products_need_2t_minus_1_points():
    local = _local_products(5, 3)                      # degree 2t-2 = 4
    assert reconstruct(local[:3]) != A * B % P          # t points are not enough
    assert reconstruct(local) == A * B % P              # 2t-1 = 5 points are


def test_too_few_parties_cannot_multiply():
    assert reconstruct(_local_products(4, 3)) != A * B % P   # n=4 < 2t-1=5


def test_degree_reduction_yields_a_fresh_degree_t_minus_1_sharing():
    n, t = 5, 3
    local = _local_products(n, t)
    lam = lagrange_coefficients_at_zero(list(range(1, n + 1)), F)
    sub = [split(local[j].y, t, n) for j in range(n)]          # party j re-shares its local product
    new = [Share(i + 1, sum(lam[j] * sub[j][i].y for j in range(n)) % P) for i in range(n)]
    assert reconstruct_checked(new, t) == A * B % P            # all 5 points lie on a degree-2 polynomial
    assert reconstruct(new[2:]) == A * B % P                   # any t of them work


# --- End-to-end over TCP, one process per party ------------------------------------

def test_secure_average():
    value, run = secure_average([10, 20, 30, 41], t=3)
    assert value == Fraction(101, 4)
    assert run.message_count == 24      # 4 inputs x 3 + 1 output wire x 4 x 3


def test_secure_dot_product():
    value, run = secure_dot_product([1, 2, 3], [4, 5, 6], t=2)
    assert value == 32
    assert run.outputs == [[32]] * 3


def test_secure_variance(variance_result):
    value, run, xs = variance_result
    assert value == Fraction(statistics.pvariance(xs)).limit_denominator(100)
    assert run.outputs == [[1834]] * 5


def test_mixed_circuit_with_chained_multiplications_matches_plaintext():
    c = Circuit(3)
    x0, x1, x2 = c.input(0), c.input(1), c.input(2)
    c.output(c.add(c.sub(c.mul(c.mul(x0, x1), x2), c.cmul(x0, 5)), c.const(1000)))
    rng = random.Random(7)
    inputs = [[rng.randrange(10**6)] for _ in range(3)]
    run = run_circuit(c, inputs, t=2)
    assert run.result == evaluate_plain(c, inputs)


def test_every_wire_is_a_consistent_degree_t_minus_1_sharing(variance_result):
    """After every multiplication the degree is back to t-1 and the value is right."""
    _, run, xs = variance_result
    truth = evaluate_wires(run.circuit, [[x] for x in xs])
    for w in range(len(run.circuit.gates)):
        pts = [Share(i + 1, run.wire_shares[i][w]) for i in range(run.n)]
        assert reconstruct_checked(pts, run.t) == truth[w]


@pytest.mark.parametrize("call", [
    lambda: secure_dot_product([1, 2, 3], [4, 5, 6], t=3),     # n=3 < 2t-1=5
    lambda: secure_variance([1, 2, 3, 4], t=3),                # n=4 < 5
    lambda: secure_average([P - 1, 5], t=2),                   # sum would wrap
    lambda: secure_dot_product([1, 2], [3], t=2),              # length mismatch
])
def test_unsafe_or_invalid_requests_are_rejected(call):
    with pytest.raises(ValueError):
        call()


# --- Auditing the wire --------------------------------------------------------------

def test_message_counts_by_round(variance_result):
    _, run, _ = variance_result
    kinds = [json.loads(m["raw"])["type"] for m in run.messages("out")]
    n, muls = 5, len(run.circuit.mul_gates)
    assert kinds.count("in") == 5 * (n - 1)            # one sharing per input gate
    assert kinds.count("mul") == muls * n * (n - 1)    # everyone re-shares at each mul gate
    assert kinds.count("open") == n * (n - 1)          # one output wire
    assert run.message_count == len(kinds) == 160


def test_wire_messages_are_well_formed_and_never_carry_an_input(variance_result):
    _, run, xs = variance_result
    for m in run.messages("out") + run.messages("in"):
        obj = json.loads(m["raw"])
        assert set(obj) == {"type", "from", "gate", "x", "y"}
        assert int(obj["y"]) not in xs


def _input_shares_seen(run, coalition, wire):
    seen = []
    for c in coalition:
        for m in run.wire_logs[c]:
            obj = json.loads(m["raw"])
            if m["dir"] == "in" and obj["type"] == "in" and obj["gate"] == wire:
                seen.append(Share(obj["x"], int(obj["y"])))
    return seen


def test_t_minus_1_colluders_learn_nothing_about_an_input_but_t_do(variance_result):
    _, run, xs = variance_result
    victim = 4                                          # input wire w4 belongs to party 4
    two = _input_shares_seen(run, [0, 1], victim)       # t - 1 = 2
    assert len(two) == 2 and reconstruct(two) != xs[victim]
    three = _input_shares_seen(run, [0, 1, 2], victim)  # t = 3
    assert len(three) == 3 and reconstruct(three) == xs[victim]
