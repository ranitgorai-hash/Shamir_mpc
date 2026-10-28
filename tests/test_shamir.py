from itertools import combinations, product

import pytest
from hypothesis import given, settings, strategies as st

from mpc import (
    DEFAULT_PRIME, PrimeField, Share, add_shares, evaluate_polynomial,
    reconstruct, scale_share, split,
)

F = PrimeField(DEFAULT_PRIME)


# --- Known-answer test (worked example from the Shamir's Secret Sharing
# Wikipedia article: p=1613, secret 1234, f(x)=1234+166x+94x^2) --------------

def test_known_vector():
    field = PrimeField(1613)
    coeffs = [1234, 166, 94]
    shares = [Share(i, evaluate_polynomial(coeffs, i, field)) for i in range(1, 7)]
    assert shares == [(1, 1494), (2, 329), (3, 965), (4, 176), (5, 1188), (6, 775)]
    assert reconstruct([shares[1], shares[2], shares[4]], field) == 1234


# --- Correctness --------------------------------------------------------------

@pytest.mark.parametrize("t,n", [(1, 1), (1, 4), (2, 3), (3, 5), (4, 7), (5, 5)])
def test_every_size_t_subset_reconstructs(t, n):
    secret = F.random_element()
    shares = split(secret, t, n)
    for subset in combinations(shares, t):
        assert reconstruct(subset) == secret


def test_more_than_t_shares_also_works():
    secret = 424242
    shares = split(secret, 3, 8)
    assert reconstruct(shares) == secret
    assert reconstruct(shares[:5]) == secret


def test_share_order_does_not_matter():
    secret = 99
    shares = split(secret, 3, 6)
    assert reconstruct([shares[4], shares[0], shares[2]]) == secret


def test_edge_secrets():
    for secret in (0, 1, DEFAULT_PRIME - 1):
        assert reconstruct(split(secret, 3, 5)[:3]) == secret


@settings(max_examples=100, deadline=None)
@given(st.integers(0, DEFAULT_PRIME - 1), st.data())
def test_property_roundtrip(secret, data):
    n = data.draw(st.integers(1, 12))
    t = data.draw(st.integers(1, n))
    shares = split(secret, t, n)
    chosen = data.draw(st.permutations(shares).map(lambda s: s[:t]))
    assert reconstruct(chosen) == secret


# --- Privacy (exhaustive, in a tiny field so it can be enumerated) --------------

def test_t_minus_1_shares_reveal_nothing_t2():
    """t=2: one share (x=1). Over all random coefficients a1, the share value is
    uniform on the field for EVERY secret, so it carries no information."""
    field = PrimeField(13)
    for secret in range(13):
        ys = sorted(
            evaluate_polynomial([secret, a1], 1, field) for a1 in range(13)
        )
        assert ys == list(range(13))


def test_t_minus_1_shares_reveal_nothing_t3():
    """t=3: two shares (x=1,2). Over all (a1,a2), the pair (y1,y2) hits every
    point of the field^2 exactly once, for every secret."""
    field = PrimeField(11)
    for secret in range(11):
        pairs = {
            (
                evaluate_polynomial([secret, a1, a2], 1, field),
                evaluate_polynomial([secret, a1, a2], 2, field),
            )
            for a1, a2 in product(range(11), repeat=2)
        }
        assert len(pairs) == 11 * 11


def test_t_minus_1_shares_do_not_reconstruct_secret():
    secret = 777
    shares = split(secret, 4, 6)
    # Fewer than t shares give a value unrelated to the secret (a miss is
    # astronomically likely in a 127-bit field).
    assert reconstruct(shares[:3]) != secret


# --- Linear homomorphism ------------------------------------------------------

def test_add_shares_gives_sum_of_secrets():
    a, b = 1000, 2345
    sa, sb = split(a, 3, 5), split(b, 3, 5)
    summed = [add_shares(x, y) for x, y in zip(sa, sb)]
    assert reconstruct(summed[:3]) == a + b


def test_sum_wraps_modulo_p():
    a, b = DEFAULT_PRIME - 1, 5
    sa, sb = split(a, 2, 3), split(b, 2, 3)
    summed = [add_shares(x, y) for x, y in zip(sa, sb)]
    assert reconstruct(summed[:2]) == (a + b) % DEFAULT_PRIME


def test_scale_share():
    shares = [scale_share(s, 7) for s in split(123, 3, 5)]
    assert reconstruct(shares[:3]) == 7 * 123


def test_add_shares_rejects_mismatched_parties():
    with pytest.raises(ValueError):
        add_shares(Share(1, 5), Share(2, 5))


# --- Input validation ---------------------------------------------------------

@pytest.mark.parametrize("secret,t,n", [
    (-1, 2, 3), (DEFAULT_PRIME, 2, 3), (5, 0, 3), (5, 4, 3), (5, 2, 0),
])
def test_split_rejects_bad_parameters(secret, t, n):
    with pytest.raises(ValueError):
        split(secret, t, n)


def test_n_must_be_below_modulus():
    with pytest.raises(ValueError):
        split(1, 2, 13, PrimeField(13))


def test_reconstruct_rejects_duplicates_and_empty():
    with pytest.raises(ValueError):
        reconstruct([Share(1, 5), Share(1, 5)])
    with pytest.raises(ValueError):
        reconstruct([])
    with pytest.raises(ValueError):
        reconstruct([Share(0, 5), Share(1, 6)])
