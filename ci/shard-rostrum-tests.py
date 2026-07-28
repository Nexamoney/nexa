#!/usr/bin/env python3

import argparse
from pathlib import Path


TEST_PATTERNS = ("feature_*.py", "rpc_*.py")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Select one deterministic shard of the Rostrum functional tests"
    )
    parser.add_argument("test_dir", type=Path)
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.count < 1:
        raise SystemExit("shard count must be at least one")
    if not 0 <= args.index < args.count:
        raise SystemExit("shard index must be between zero and count minus one")
    if not args.test_dir.is_dir():
        raise SystemExit(f"test directory does not exist: {args.test_dir}")

    tests = sorted(
        {
            test
            for pattern in TEST_PATTERNS
            for test in args.test_dir.glob(pattern)
            if test.is_file()
        }
    )
    selected = set(tests[args.index :: args.count])
    if not selected:
        raise SystemExit(f"shard {args.index} does not contain any tests")

    excluded_dir = args.test_dir / ".ci-unselected"
    excluded_dir.mkdir()
    for test in tests:
        if test not in selected:
            test.rename(excluded_dir / test.name)

    print(f"Rostrum test shard {args.index + 1}/{args.count}:")
    for test in sorted(selected):
        print(f"  {test.name}")


if __name__ == "__main__":
    main()
