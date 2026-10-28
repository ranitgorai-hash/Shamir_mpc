# Shamir Secret Sharing & Secure MPC (educational)

Phase 1: tested core library for (t, n) threshold secret sharing over GF(p).
Phase 2: secure sum across n party processes talking over real TCP sockets.
Phase 3 + 4: BGW-style multiplication (secure average, dot product, variance) and an HTML dashboard of each party's view.

## What it does
- `mpc/field.py` - prime-field arithmetic GF(p), default p = 2^127 - 1, Miller-Rabin check on the modulus
- `mpc/shamir.py` - `split`, `reconstruct` (Lagrange at x = 0), and share-level `add_shares` / `scale_share` (linear homomorphism, the basis of secure sum)

```python
from mpc import split, reconstruct, add_shares

shares = split(secret=123456789, t=3, n=5)
assert reconstruct(shares[:3]) == 123456789        # any 3 of 5 work

a, b = split(1000, 3, 5), split(2345, 3, 5)
total = [add_shares(x, y) for x, y in zip(a, b)]   # each party adds locally
assert reconstruct(total[:3]) == 3345              # sum revealed, inputs never were
```

## Secure sum over TCP (Phase 2)
Each party runs in its own OS process and listens on its own localhost port.

```
python -m mpc.demo 1000 2500 3200 --t 2
```
```python
from mpc import run_secure_sum
run = run_secure_sum([1000, 2500, 3200], t=2)
run.totals          # [6700, 6700, 6700]: every party learns only the total
run.message_count   # 12 = 2 rounds x n(n-1)
```
Protocol: (1) each party shares its input and sends share j privately to party j;
(2) each party adds the shares it holds (a share of the total, by linearity);
(3) parties exchange summed shares and interpolate the total. Every message is
recorded in `run.wire_logs`, so tests audit exactly what crossed the network.

| File | Role |
|---|---|
| `mpc/net.py` | length-prefixed JSON framing, connect-with-retry |
| `mpc/party.py` | one party's protocol (`run_party`, asyncio) |
| `mpc/runner.py` | spawns n processes, collects totals and wire logs (`run_secure_sum`) |
| `mpc/demo.py` | command-line demo |

## Multiplication, statistics and the dashboard (Phase 3 + 4)
Circuits of add / subtract / constant-multiply / multiply gates are evaluated on
secret-shared wires (`mpc/circuit.py`, `mpc/bgw.py`). Additions are local. A multiplication
makes each party multiply its two shares (a point on a degree 2t-2 polynomial), re-share
that product with a fresh degree t-1 polynomial, and combine the sub-shares with the
Lagrange weights at 0. The result is a fresh degree t-1 sharing of the product. This needs
n >= 2t-1. Outputs are opened with a consistency check (`reconstruct_checked`).

```python
from mpc import secure_average, secure_dot_product, secure_variance

if __name__ == "__main__":   # required: parties are spawned as separate processes
    avg, run = secure_average([10, 20, 30, 41], t=3)            # Fraction(101, 4)
    dot, run = secure_dot_product([1, 2, 3], [4, 5, 6], t=2)     # 32
    var, run = secure_variance([12, 7, 30, 21, 9], t=3)          # Fraction(1834, 25) = 73.36
```
Variance reveals only n^2 * Var, not the mean or the sum separately.

Dashboard: `python -m mpc.dashboard variance 12 7 30 21 9 --t 3 -o dashboard.html` writes one
self-contained HTML file. It shows the circuit, message counts per round, each party's private
input, the share it holds on every wire, every message it sent and received, and a collusion
explorer: tick any set of parties and see which private inputs their pooled shares can
reconstruct (only when they hold at least t shares of one input).

| File | Role |
|---|---|
| `mpc/circuit.py` | circuit builder, plaintext reference evaluator, sum / dot / variance circuits |
| `mpc/bgw.py` | one party's circuit evaluation (inputs, gates, degree reduction, opening) |
| `mpc/apps.py` | `secure_average`, `secure_dot_product`, `secure_variance` |
| `mpc/dashboard.py` | HTML dashboard generator and CLI |

## Run the tests
```
pip install -r requirements.txt
python -m pytest -q
```
77 tests (32 core + 16 protocol + 29 multiplication and dashboard): field axioms (property-based), a known-answer vector, every size-t subset
reconstructs, order independence, edge secrets, and **exhaustive privacy proofs in
tiny fields** (t-1 shares are uniformly distributed for every secret).
Protocol tests: all parties agree on the total, wraparound mod p, exact message
counts, every sent message received once, **no private input ever appears in any
message**, t-1 colluding parties cannot recover a victim's input (t can), bad
parameters rejected, clean failure when peers never start, framing edge cases.

## Threat model
Semi-honest (honest-but-curious) parties; up to t-1 colluding parties learn nothing.
Out of scope: malicious parties, network attackers, side channels. The TCP links are
plaintext on localhost and stand in for the protocol's private channels; a real
deployment needs mutually authenticated TLS. Educational code,
not production cryptography.

## Roadmap
- Phase 2 (done): n party processes exchanging shares over TCP, end-to-end secure sum
- Phase 3 + 4 (done): BGW multiplication, average / dot product / variance, per-party dashboard
- Phase 5: benchmarks vs n and t, plus a t-1 collusion attack demo
