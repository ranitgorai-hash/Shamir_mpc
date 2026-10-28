import pytest
from hypothesis import given, strategies as st

from mpc import DEFAULT_PRIME, PrimeField, is_probable_prime

F = PrimeField(DEFAULT_PRIME)
elem = st.integers(min_value=0, max_value=DEFAULT_PRIME - 1)


def test_default_prime_is_prime():
    assert is_probable_prime(2**127 - 1)


def test_primality_rejects_composites_and_carmichael():
    for n in (0, 1, 4, 100, 561, 1105, 2**127 - 3 * 2**64):
        assert not is_probable_prime(n)
    for n in (2, 3, 13, 1613, 7919):
        assert is_probable_prime(n)


def test_non_prime_modulus_rejected():
    with pytest.raises(ValueError):
        PrimeField(15)


def test_inverse_of_zero_raises():
    with pytest.raises(ZeroDivisionError):
        F.inv(0)


@given(elem.filter(lambda a: a != 0))
def test_inverse_property(a):
    assert F.mul(a, F.inv(a)) == 1


@given(elem, elem, elem)
def test_field_axioms(a, b, c):
    assert F.add(a, b) == F.add(b, a)
    assert F.mul(a, F.add(b, c)) == F.add(F.mul(a, b), F.mul(a, c))
    assert F.sub(F.add(a, b), b) == a


def test_random_element_in_range():
    assert all(F.contains(F.random_element()) for _ in range(200))
