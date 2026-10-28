import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from mpc import DEFAULT_PRIME, split
from mpc.dashboard import dashboard_data, render_dashboard

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def html(variance_result):
    _, run, _ = variance_result
    return render_dashboard(run, "Secure variance", "n²·Var = 1834")


def _data(html):
    return json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S).group(1))


def test_embedded_data_matches_the_run(html, variance_result):
    _, run, xs = variance_result
    d = _data(html)
    assert (d["n"], d["t"], d["result"], d["messages"]) == (5, 3, "1834", 160)
    assert len(d["parties"]) == 5 and len(d["gates"]) == len(run.circuit.gates)
    assert d["inputs"] == [[str(x)] for x in xs]


def test_party_logs_in_the_page_never_contain_an_input(html, variance_result):
    _, _, xs = variance_result
    for party in _data(html)["parties"]:
        for entry in party["log"]:
            assert int(entry["msg"]["y"]) not in xs


def test_page_is_self_contained(html):
    assert "https://" not in html and "http://" not in html and "src=" not in html
    assert html.count("</script>") == 2


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_javascript_is_valid_and_its_lagrange_matches_python(html):
    code = html.split("<script>")[1].split("</script>")[0]
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(code)
    subprocess.run(["node", "--check", f.name], check=True)
    math = html.split("// BEGIN MATH")[1].split("// END MATH")[0]
    secret = 123456789012345678901234567890
    pts = json.dumps([[s.x, str(s.y)] for s in split(secret, 3, 5)[1:4]])
    script = f'const P = BigInt("{DEFAULT_PRIME}");\n{math}\nconsole.log(lagrange0({pts}.map(([x, y]) => [BigInt(x), BigInt(y)])).toString());'
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout.strip()
    assert out == str(secret)


def test_command_line_writes_a_dashboard(tmp_path):
    out = tmp_path / "d.html"
    subprocess.run(
        [sys.executable, "-m", "mpc.dashboard", "variance", "12", "7", "30", "21", "9", "--t", "3", "-o", str(out)],
        cwd=ROOT, check=True, capture_output=True, timeout=120,
    )
    text = out.read_text(encoding="utf-8")
    assert "Secure variance" in text and "73.36" in text
