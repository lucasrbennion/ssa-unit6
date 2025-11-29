"""
main.py

Entry point for running the smart warehouse IoT experiments.
"""

from __future__ import annotations

import argparse
import csv
from typing import Dict, Any

from experiment import run_experiment, summarise_results, print_summary


def save_results_to_csv(path: str, results: Dict[str, Any]) -> None:
    """
    Save raw message-level records to a CSV file for later inspection.
    """
    records = results["records"]
    if not records:
        return

    fieldnames = list(records[0].keys())

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smart warehouse IoT security experiment runner"
    )
    parser.add_argument(
        "--mode",
        choices=["weak", "secure"],
        required=True,
        help="Security mode for the controller",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to save raw results as CSV",
    )
    parser.add_argument(
        "--legit-per-device",
        type=int,
        default=50,
        help="Number of legitimate messages per device",
    )
    parser.add_argument(
        "--rogue-messages",
        type=int,
        default=100,
        help="Number of rogue messages to send",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    config = {
        "num_legit_devices": 3,
        "num_legit_messages_per_device": args.legit_per_device,
        "num_rogue_messages": args.rogue_messages,
        "latency_range_ms": (10.0, 100.0),
        "loss_probability": 0.05,
        "security_overhead_ms": 5.0,
    }

    results = run_experiment(mode=args.mode, config=config)
    summary = summarise_results(results)
    print_summary(summary)

    if args.output:
        save_results_to_csv(args.output, results)
        print(f"Raw results saved to {args.output}")


if __name__ == "__main__":
    main()
