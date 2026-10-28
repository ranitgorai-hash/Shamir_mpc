"""Demo: python -m mpc.demo 1000 2500 3200 --t 2"""

import argparse
import json

from .runner import run_secure_sum


def main() -> None:
    ap = argparse.ArgumentParser(description="Secure sum over TCP, one process per party")
    ap.add_argument("inputs", nargs="+", type=int, help="private input of each party")
    ap.add_argument("--t", type=int, default=2, help="sharing threshold (default 2)")
    args = ap.parse_args()

    run = run_secure_sum(args.inputs, t=args.t)
    print(f"{run.n} parties, threshold t={run.t}")
    print(f"plain sum      : {sum(args.inputs)}")
    print(f"parties' totals: {run.totals}")
    print(f"messages sent  : {run.message_count}")
    sample = next(m for m in run.messages('out') if '"share"' in m["raw"])
    print(f"sample message : {sample['raw']}")
    print("(the y value is a random-looking share, not anyone's input)")
    assert all(total == sum(args.inputs) for total in run.totals)


if __name__ == "__main__":
    main()
