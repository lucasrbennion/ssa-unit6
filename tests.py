"""
tests.py

Lightweight tests for the smart warehouse IoT simulation.

Run with:
    python tests.py
"""

from __future__ import annotations

from typing import Dict, Any

from model import (
    NetworkSimulator,
    Controller,
    Device,
    RogueDevice,
    Message,
)
from experiment import run_experiment, summarise_results


def test_secure_authentication_success() -> None:
    """
    Legitimate device with correct API key should be accepted in secure mode.
    """
    controller = Controller(mode="secure")
    network = NetworkSimulator(loss_probability=0.0)

    controller.register_device("device_1", role="sensor", api_key="key-device_1")
    device = Device(
        device_id="device_1",
        role="sensor",
        api_key="key-device_1",
        network=network,
        controller=controller,
    )

    result = device.send_action("send_status")
    assert result.delivered is True
    assert result.accepted is True
    assert result.authorised is True


def test_secure_authentication_failure_wrong_key() -> None:
    """
    Device with wrong API key should be rejected in secure mode.
    """
    controller = Controller(mode="secure")
    network = NetworkSimulator(loss_probability=0.0)

    controller.register_device("device_1", role="sensor", api_key="key-device_1")
    # Wrong key
    device = Device(
        device_id="device_1",
        role="sensor",
        api_key="bad-key",
        network=network,
        controller=controller,
    )

    result = device.send_action("send_status")
    assert result.delivered is True
    assert result.accepted is False
    assert result.authorised is False


def test_secure_rbac_blocks_forbidden_action() -> None:
    """
    RBAC should block a sensor from performing a privileged action such as 'shutdown'.
    """
    controller = Controller(mode="secure")
    network = NetworkSimulator(loss_probability=0.0)

    controller.register_device("device_1", role="sensor", api_key="key-device_1")
    device = Device(
        device_id="device_1",
        role="sensor",
        api_key="key-device_1",
        network=network,
        controller=controller,
    )

    result = device.send_action("shutdown")
    assert result.delivered is True
    assert result.accepted is False
    assert result.authorised is False


def test_network_can_drop_messages() -> None:
    """
    Network simulator should be able to drop messages when loss_probability=1.0.
    """
    controller = Controller(mode="weak")
    # No need to register device for this test; focus is on delivery flag
    network = NetworkSimulator(loss_probability=1.0)

    message = Message(
        device_id="any",
        role="sensor",
        action="send_status",
        payload={},
        credentials=None,
    )

    result = network.send(message, controller)
    assert result.delivered is False
    assert result.accepted is False
    assert result.authorised is False


def test_experiment_runs_and_has_basic_structure() -> None:
    """
    End-to-end check that run_experiment and summarise_results work.
    """
    config: Dict[str, Any] = {
        "num_legit_devices": 2,
        "num_legit_messages_per_device": 10,
        "num_rogue_messages": 10,
        "latency_range_ms": (10.0, 20.0),
        "loss_probability": 0.0,
        "security_overhead_ms": 5.0,
    }

    results_secure = run_experiment(mode="secure", config=config)
    summary_secure = summarise_results(results_secure)

    assert "mode" in summary_secure
    assert summary_secure["mode"] == "secure"
    assert summary_secure["total_messages"] == 2 * 10 + 10
    assert summary_secure["total_legitimate"] == 2 * 10
    assert summary_secure["total_rogue"] == 10

    # Weak mode should also run without crashing
    results_weak = run_experiment(mode="weak", config=config)
    summary_weak = summarise_results(results_weak)
    assert summary_weak["mode"] == "weak"


def run_all_tests() -> None:
    """
    Run all test functions in this module.
    """
    test_secure_authentication_success()
    test_secure_authentication_failure_wrong_key()
    test_secure_rbac_blocks_forbidden_action()
    test_network_can_drop_messages()
    test_experiment_runs_and_has_basic_structure()
    print("All tests passed.")


if __name__ == "__main__":
    run_all_tests()
