"""
experiment.py

Runs experiments using the smart warehouse IoT model to compare
weak vs secure security modes in terms of unauthorised actions
and latency / reliability.
"""

from __future__ import annotations

from typing import Dict, Any, List, Tuple

from model import (
    NetworkSimulator,
    Controller,
    Device,
    RogueDevice,
    MessageResult,
)


# -----------------------------
# Helpers for experiment setup
# -----------------------------


def _create_devices_and_controller(
    mode: str,
    config: Dict[str, Any],
) -> Tuple[Controller, NetworkSimulator, List[Device], RogueDevice]:
    """
    Initialise controller, network, legitimate devices and a rogue device
    according to the supplied configuration.
    """
    network = NetworkSimulator(
        latency_range_ms=config.get("latency_range_ms", (10.0, 100.0)),
        loss_probability=config.get("loss_probability", 0.05),
    )

    controller = Controller(
        mode=mode,
        security_overhead_ms=config.get("security_overhead_ms", 5.0),
    )

    num_legit_devices = config.get("num_legit_devices", 3)

    # Assign simple roles in a round-robin fashion
    role_cycle = ["sensor", "robot", "viewer"]
    legit_devices: List[Device] = []

    for i in range(num_legit_devices):
        device_id = f"device_{i+1}"
        role = role_cycle[i % len(role_cycle)]

        # Per-device API key only matters in secure mode
        api_key = f"key-{device_id}" if mode == "secure" else None

        controller.register_device(device_id=device_id, role=role, api_key=api_key)

        device = Device(
            device_id=device_id,
            role=role,
            api_key=api_key,
            network=network,
            controller=controller,
        )
        legit_devices.append(device)

    # Rogue device: may claim to be a robot with spoofed / invalid credentials
    rogue_id = config.get("rogue_device_id", "rogue_1")
    rogue_role = config.get("rogue_role", "robot")

    if mode == "secure":
        # Use an invalid API key to represent a spoof attempt
        rogue_key = config.get("rogue_api_key", "invalid-key")
    else:
        # In weak mode credentials are effectively ignored
        rogue_key = None

    rogue_device = RogueDevice(
        device_id=rogue_id,
        claimed_role=rogue_role,
        spoofed_credentials=rogue_key,
        network=network,
        controller=controller,
    )

    return controller, network, legit_devices, rogue_device


def _choose_legitimate_action(role: str) -> str:
    """
    Pick a typical, legitimate action for a given device role.
    """
    if role == "sensor":
        return "send_status"
    if role == "viewer":
        return "read_status"
    # robot default
    return "move"


def _choose_malicious_action() -> str:
    """
    Choose an action that is likely to be considered sensitive / higher risk.
    """
    # Shutdown or privileged movement-type command are good candidates
    return "shutdown"


# -----------------------------
# Core experiment functions
# -----------------------------


def run_experiment(mode: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a single experiment for a given security mode and configuration.

    Returns a dictionary containing:
      - mode
      - config
      - records: list of message-level results
    """
    controller, network, legit_devices, rogue_device = _create_devices_and_controller(
        mode=mode,
        config=config,
    )

    num_legit_messages_per_device = config.get("num_legit_messages_per_device", 100)
    num_rogue_messages = config.get("num_rogue_messages", 100)

    records: List[Dict[str, Any]] = []

    # Legitimate traffic
    for device in legit_devices:
        for _ in range(num_legit_messages_per_device):
            action = _choose_legitimate_action(device.role)
            result: MessageResult = device.send_action(action=action)

            records.append(
                {
                    "source": "legitimate",
                    "device_id": device.device_id,
                    "role": device.role,
                    "action": action,
                    "delivered": result.delivered,
                    "latency_ms": result.latency_ms,
                    "accepted": result.accepted,
                    "authorised": result.authorised,
                    "reason": result.reason,
                }
            )

    # Malicious / rogue traffic
    for _ in range(num_rogue_messages):
        action = _choose_malicious_action()
        result = rogue_device.send_malicious_action(action=action)

        records.append(
            {
                "source": "rogue",
                "device_id": rogue_device.device_id,
                "role": rogue_device.role,
                "action": action,
                "delivered": result.delivered,
                "latency_ms": result.latency_ms,
                "accepted": result.accepted,
                "authorised": result.authorised,
                "reason": result.reason,
            }
        )

    return {
        "mode": mode,
        "config": config,
        "records": records,
    }


def summarise_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute aggregate statistics from raw message-level results.
    """
    records = results["records"]

    total_messages = len(records)
    legit_records = [r for r in records if r["source"] == "legitimate"]
    rogue_records = [r for r in records if r["source"] == "rogue"]

    def _avg_latency(rs: List[Dict[str, Any]]) -> float:
        delivered = [r for r in rs if r["delivered"]]
        if not delivered:
            return 0.0
        return sum(r["latency_ms"] for r in delivered) / len(delivered)

    # Security outcomes
    rogue_accepted = [
        r for r in rogue_records if r["accepted"]
    ]
    rogue_unauthorised_accepted = [
        r for r in rogue_records if r["accepted"] and not r["authorised"]
    ]

    legit_accepted = [
        r for r in legit_records if r["accepted"]
    ]

    summary = {
        "mode": results["mode"],
        "total_messages": total_messages,
        "total_legitimate": len(legit_records),
        "total_rogue": len(rogue_records),
        "legitimate_accepted": len(legit_accepted),
        "rogue_accepted": len(rogue_accepted),
        "rogue_unauthorised_accepted": len(rogue_unauthorised_accepted),
        "avg_latency_all_ms": _avg_latency(records),
        "avg_latency_legitimate_ms": _avg_latency(legit_records),
        "avg_latency_rogue_ms": _avg_latency(rogue_records),
    }

    return summary


def print_summary(summary: Dict[str, Any]) -> None:
    """
    Pretty-print a summary dictionary to the console.
    """
    mode = summary["mode"]
    print(f"=== Summary for mode: {mode} ===")
    print(f"Total messages:           {summary['total_messages']}")
    print(f"  Legitimate messages:    {summary['total_legitimate']}")
    print(f"  Rogue messages:         {summary['total_rogue']}")
    print()
    print(f"Legitimate accepted:      {summary['legitimate_accepted']}")
    print(f"Rogue accepted (any):     {summary['rogue_accepted']}")
    print(
        f"Rogue accepted (unauth.): {summary['rogue_unauthorised_accepted']}"
    )
    print()
    print(
        f"Average latency (all):    {summary['avg_latency_all_ms']:.2f} ms"
    )
    print(
        f"Average latency (legit):  {summary['avg_latency_legitimate_ms']:.2f} ms"
    )
    print(
        f"Average latency (rogue):  {summary['avg_latency_rogue_ms']:.2f} ms"
    )
    print("===============================")


# -----------------------------
# Quick manual run
# -----------------------------

if __name__ == "__main__":
    # Default configuration for a quick sanity check
    base_config = {
        "num_legit_devices": 3,
        "num_legit_messages_per_device": 50,
        "num_rogue_messages": 100,
        "latency_range_ms": (10.0, 100.0),
        "loss_probability": 0.05,
        "security_overhead_ms": 5.0,
    }

    for mode in ("weak", "secure"):
        res = run_experiment(mode=mode, config=base_config)
        summ = summarise_results(res)
        print_summary(summ)
        print()
