#Model Smart Warehouse  
"""
model.py

Core domain model for the smart warehouse IoT simulation.
Defines devices, rogue devices, the controller (hub) and a simple network
simulator used to study security and availability trade-offs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple, Any
import random


# -----------------------------
# Data structures
# -----------------------------


@dataclass
class Message:
    """
    Simple message structure representing a request from a device to the controller.
    """
    device_id: str
    role: str
    action: str
    payload: Dict[str, Any]
    credentials: Optional[str]  # e.g. API key or shared secret


@dataclass
class MessageResult:
    """
    Result of sending a message through the network and controller.
    """
    delivered: bool
    latency_ms: float
    accepted: bool
    authorised: bool
    reason: str


# -----------------------------
# Network simulator
# -----------------------------


class NetworkSimulator:
    """
    Simulates basic network behaviour: latency and probabilistic message loss.
    """

    def __init__(
        self,
        latency_range_ms: Tuple[float, float] = (10.0, 100.0),
        loss_probability: float = 0.05,
    ) -> None:
        self.latency_range_ms = latency_range_ms
        self.loss_probability = loss_probability

    def send(self, message: Message, controller: "Controller") -> MessageResult:
        """
        Route a message to the controller, possibly dropping it and
        always adding simulated latency.
        """
        latency_ms = random.uniform(*self.latency_range_ms)

        # Simulate message loss
        if random.random() < self.loss_probability:
            return MessageResult(
                delivered=False,
                latency_ms=latency_ms,
                accepted=False,
                authorised=False,
                reason="network_drop",
            )

        # Hand off to controller
        decision = controller.process_message(message)

        return MessageResult(
            delivered=True,
            latency_ms=latency_ms + decision["security_overhead_ms"],
            accepted=decision["accepted"],
            authorised=decision["authorised"],
            reason=decision["reason"],
        )


# -----------------------------
# Controller / Hub
# -----------------------------


@dataclass
class RegisteredDevice:
    device_id: str
    role: str
    api_key: Optional[str]


class Controller:
    """
    Controller / hub responsible for authenticating devices, enforcing RBAC
    and deciding whether to execute requested actions.
    """

    def __init__(
        self,
        mode: str = "weak",
        rbac_policies: Optional[Dict[str, Set[str]]] = None,
        security_overhead_ms: float = 5.0,
    ) -> None:
        """
        mode: "weak" or "secure"
        rbac_policies: mapping of role -> allowed actions
        security_overhead_ms: extra processing time to simulate security cost
        """
        if mode not in {"weak", "secure"}:
            raise ValueError("mode must be 'weak' or 'secure'")

        self.mode = mode
        self.device_registry: Dict[str, RegisteredDevice] = {}
        self.security_overhead_ms = security_overhead_ms

        # Default RBAC: adjust in experiments as needed
        self.rbac_policies: Dict[str, Set[str]] = rbac_policies or {
            "sensor": {"send_status"},
            "robot": {"move", "shutdown", "send_status"},
            "viewer": {"read_status"},
        }

    def register_device(self, device_id: str, role: str, api_key: Optional[str]) -> None:
        """
        Register a legitimate device with an optional API key.
        """
        self.device_registry[device_id] = RegisteredDevice(device_id, role, api_key)

    # ---- internal helpers ----

    def _authenticate_weak(self, message: Message) -> Tuple[bool, str]:
        """
        Very weak authentication: checks only that the device_id is known.
        Ignores API keys and assumes shared / default credentials.
        """
        if message.device_id in self.device_registry:
            return True, "auth_ok_weak"
        return False, "unknown_device"

    def _authenticate_secure(self, message: Message) -> Tuple[bool, str]:
        """
        Stronger authentication: checks device_id and per-device API key.
        """
        registered = self.device_registry.get(message.device_id)
        if not registered:
            return False, "unknown_device"

        if not registered.api_key or not message.credentials:
            return False, "missing_api_key"

        if registered.api_key != message.credentials:
            return False, "invalid_api_key"

        return True, "auth_ok_secure"

    def _authorise(self, role: str, action: str) -> Tuple[bool, str]:
        """
        Check whether a given role is allowed to perform the requested action.
        """
        allowed_actions = self.rbac_policies.get(role, set())
        if action in allowed_actions:
            return True, "authorised"
        return False, "forbidden_action"

    # ---- public interface ----

    def process_message(self, message: Message) -> Dict[str, Any]:
        """
        Apply authentication and authorisation rules based on the configured mode
        and decide whether to accept the message.
        Returns a dictionary used by the NetworkSimulator.
        """
        # Simulated security processing overhead applied in all modes
        overhead_ms = self.security_overhead_ms if self.mode == "secure" else 0.0

        # Authentication
        if self.mode == "weak":
            authenticated, auth_reason = self._authenticate_weak(message)
        else:
            authenticated, auth_reason = self._authenticate_secure(message)

        if not authenticated:
            # In weak mode you might still (optionally) accept unauthenticated messages.
            if self.mode == "weak":
                # Dangerous behaviour: accept some unauthenticated messages anyway.
                accept_anyway = random.random() < 0.5
                if accept_anyway:
                    return {
                        "accepted": True,
                        "authorised": False,
                        "reason": f"accepted_without_auth:{auth_reason}",
                        "security_overhead_ms": overhead_ms,
                    }
            return {
                "accepted": False,
                "authorised": False,
                "reason": auth_reason,
                "security_overhead_ms": overhead_ms,
            }

        # Authorisation (RBAC) only used meaningfully in secure mode
        if self.mode == "secure":
            authorised, authz_reason = self._authorise(message.role, message.action)
            if not authorised:
                return {
                    "accepted": False,
                    "authorised": False,
                    "reason": authz_reason,
                    "security_overhead_ms": overhead_ms,
                }
            return {
                "accepted": True,
                "authorised": True,
                "reason": "secure_accept",
                "security_overhead_ms": overhead_ms,
            }

        # Weak mode: once authenticated, almost everything is allowed
        return {
            "accepted": True,
            "authorised": True,
            "reason": "weak_accept_no_rbac",
            "security_overhead_ms": overhead_ms,
        }


# -----------------------------
# Device and RogueDevice
# -----------------------------


class Device:
    """
    Legitimate client device in the smart warehouse (e.g. sensor or robot).
    """

    def __init__(
        self,
        device_id: str,
        role: str,
        api_key: Optional[str],
        network: NetworkSimulator,
        controller: Controller,
    ) -> None:
        self.device_id = device_id
        self.role = role
        self.api_key = api_key
        self.network = network
        self.controller = controller

    def send_action(self, action: str, payload: Optional[Dict[str, Any]] = None) -> MessageResult:
        """
        Create and send a message to the controller via the network.
        """
        if payload is None:
            payload = {}

        message = Message(
            device_id=self.device_id,
            role=self.role,
            action=action,
            payload=payload,
            credentials=self.api_key,
        )
        return self.network.send(message, self.controller)


class RogueDevice(Device):
    """
    Rogue or compromised device attempting unauthorised actions.
    """

    def __init__(
        self,
        device_id: str,
        claimed_role: str,
        spoofed_credentials: Optional[str],
        network: NetworkSimulator,
        controller: Controller,
    ) -> None:
        # Rogue device may not be registered at all; it just claims an ID and role.
        super().__init__(
            device_id=device_id,
            role=claimed_role,
            api_key=spoofed_credentials,
            network=network,
            controller=controller,
        )

    def send_malicious_action(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> MessageResult:
        """
        Send an action that should not be allowed for this device or role.
        """
        return self.send_action(action=action, payload=payload)
