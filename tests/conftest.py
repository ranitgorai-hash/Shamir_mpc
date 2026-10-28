import pytest

from mpc import secure_variance

VARIANCE_INPUTS = [12, 7, 30, 21, 9]


@pytest.fixture(scope="session")
def variance_result():
    """One shared 5-party, t=3 variance run (needs n >= 2t-1 = 5)."""
    value, run = secure_variance(VARIANCE_INPUTS, t=3)
    return value, run, VARIANCE_INPUTS
