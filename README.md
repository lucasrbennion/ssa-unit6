---

# **Smart Warehouse IoT Security Simulation**

### *Evaluating Authentication and RBAC Controls in a Distributed IoT Environment*

## **1. Introduction**

This prototype models a simplified smart-warehouse Internet of Things (IoT) environment to investigate security and reliability trade-offs in distributed systems. The simulation focuses on comparing a **weak security configuration** (shared credentials and minimal checks) with a **stronger configuration** that uses **per-device authentication** and **role-based access control (RBAC)**. The code demonstrates the interactions between a client device and a controller, incorporates elements such as latency and message loss and evaluates how these differences affect the system’s vulnerability to unauthorised actions.

The work builds on the vulnerabilities identified in Unit 3 (e.g., weak credentials, rogue-device spoofing and over-privileged applications). The simulation provides quantitative evidence to address the chosen hypothesis and highlights how improved security controls change system behaviour.

---

## **2. Research Question and Hypothesis**

**Research Question:**
Does enforcing per-device authentication and RBAC on a warehouse IoT controller significantly reduce unauthorised actions while imposing only a modest performance overhead?

**Hypothesis:**
*“In a smart warehouse IoT system, enforcing per-device authentication and RBAC at the controller significantly reduces successful unauthorised commands from rogue devices, while adding only a small increase in average message latency compared with a weak-credential baseline.”*

---

## **3. Model Overview**

The prototype simulates three main components:

* **Device (legitimate):** A registered IoT component such as a sensor, viewer or robot. Devices can send permitted actions using their assigned roles and, in secure mode, an API key.
* **RogueDevice:** An unregistered or spoofed client attempting privileged actions such as `shutdown`. It challenges the system’s authentication and authorisation controls.
* **Controller (Hub):** Authenticates devices and enforces RBAC in secure mode. In weak mode, it only checks device identifiers and may accept unauthorised messages, reflecting insecure real-world deployments.
* **NetworkSimulator:** Introduces random latency and message loss to replicate common distributed-system challenges and interactions flow through the network layer. 

---

## **4. Experiment Design**

The experiment compares two operational modes:

1. **Weak Security Mode**

   * Basic ID-based checks
   * No per-device API keys
   * No RBAC restrictions
   * High susceptibility to rogue-device success

2. **Secure Mode**

   * Per-device API keys
   * RBAC enforcement (e.g., sensors cannot perform `shutdown`)
   * Simulated security-processing overhead

### **Traffic Generation**

* Three legitimate devices send routine actions (e.g., `send_status`, `move`, `read_status`).
* A rogue device sends only malicious actions (`shutdown`).
* Experiments generate:

  * *N* legitimate messages per device
  * *N* rogue messages
* Latency and message-loss probability are held constant across both scenarios.

### **Metrics Collected**

* Number of legitimate messages accepted
* Number of rogue messages accepted
* Number of unauthorised messages incorrectly accepted
* Average message latency
* Differences in behaviour between weak and secure modes

---

## **5. Summary of Results**

Refer the Testing Results summary word file "Unit 6 - Individual Project Code Development - Testing Results - Lucas Bennion.docx"

---

## **6. Vulnerabilities Addressed and Remaining Gaps**

### **Mitigated Vulnerabilities**

* **Default or weak credentials:** Secure mode enforces per-device API keys.
* **Rogue-device spoofing:** Authentication rejects invalid keys, and RBAC prevents privilege escalation.
* **Over-privileged applications:** RBAC limits actions by device role.

### **Unmodelled or Partially Addressed Vulnerabilities**

* Cloud misconfiguration
* Ransomware and data corruption at the controller level
* Man-in-the-middle attacks
* Firmware/physical tampering

These omissions are intentional due to scope constraints and the 1300-word limit.

---

## **7. How to Run the Simulation**

Ensure all files (`model.py`, `experiment.py`, `main.py`, `tests.py`) are in the same directory.

### **Run experiments**

Weak mode:

```bash
python main.py --mode weak
```

Secure mode:

```bash
python main.py --mode secure
```

Save raw message-level results:

```bash
python main.py --mode secure --output secure_results.csv
```

### **Run tests**

```bash
python tests.py
```

The terminal output has been captured as evidence in the "Unit 6 - Individual Project Code Development - Testing Results - Lucas Bennion.docx"

---

## **8. Limitations and Future Enhancements**

* The simulation uses simplified authentication rather than real cryptography.
* The network model is deliberately minimal and does not include congestion, jitter correlation or packet batching.
* The controller represents a single point of coordination; real smart-warehouse systems may involve multiple hubs or cloud services.
* Future work could model encryption overhead, message signing, hierarchical controllers or multi-controller load balancing.

---

## **9. Repository Structure**

```
model.py
experiment.py
main.py
tests.py
README.md
outputs/    (testing output in the CVS)
```