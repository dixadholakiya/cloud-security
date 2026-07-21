# Cloud Security Threat & Attack Vector Lab Suite

Welcome to the Cloud Security Hands-on Lab Suite. This directory contains executable command-line Python scripts designed to simulate and demonstrate the mechanics of four critical cloud-specific vulnerability classes:

1. **SOAP XML Wrapping (Message-Level Signature Bypassing)**
2. **Cross-VM Side Channel (Hardware Cache Sniffing)**
3. **SSRF-to-IMDS Metadata Spoofing (Credential Theft)**
4. **Man-in-the-Cloud (MitC) OAuth Token Hijacking**

These labs are designed for educational purposes to illustrate the differences between **Vulnerable** configurations and **Remediated (Secure)** profiles.

---

## Getting Started

To run the interactive lab controller, execute the main script using Python 3:

```bash
python3 run_lab.py
```

This launches a command-line menu where you can select, execute, and inspect each attack vector.

---

## Lab Details & Mechanisms

### 1. SOAP XML Wrapping Lab (`soap_wrapping_lab.py`)
- **Vulnerability**: A logical discrepancy where the signature verification engine validates one element (referencing a unique ID) while the backend application parses and executes a duplicate element (which is unsigned).
- **Vulnerable Run**: The verifier verifies `ID="Original"` and grants access, but the business logic queries the document loosely using `getElementsByTagName("Body")` and picks up the attacker's duplicate malicious payload first.
- **Remediation**: The verifier validates the payload structure using strict XSD schema validation (throwing an error on duplicate tags) or absolute XPath mapping (`/Envelope/Body[@wsu:Id='Original']`) to bind signature verification directly to executed code blocks.

### 2. Cross-VM Side Channel Lab (`cross_vm_cache_lab.py`)
- **Vulnerability**: Shared L3/LLC CPU caches in multi-tenant environments allow a co-resident VM to map the memory access patterns of cryptographic operations in a concurrent victim VM.
- **Vulnerable Run**: The script simulates a 16-slot L3 cache. It executes the **Prime** phase (filling the cache), runs the **Victim Cryptographic function** (accessing key-dependent slots and evicting attacker data), and performs the **Probe** phase (measuring timing latencies). The timing spikes (cache misses) reveal the victim's operations, allowing key bit extraction.
- **Remediation**: Enables constant-time crypto algorithms (making memory access uniform and timing-neutral) or cache partitioning (such as Intel CAT, isolating cache lines between tenants).

### 3. SSRF-to-IMDS Lab (`ssrf_imds_lab.py`)
- **Vulnerability**: Server-Side Request Forgery allows an external attacker to force a web server to make requests internally. In cloud instances, querying `http://169.254.169.254/` fetches the temporary security credentials of the VM's active IAM role.
- **Vulnerable Run**: The script boots a local Web Server (representing the vulnerable web app) and a local Metadata Service. The attacker triggers a request to query the metadata credentials endpoint. The web server blindly proxies the GET request, exfiltrating the JSON credentials payload to the attacker.
- **Remediation**: Enables input sanitation (blocklisting private IP ranges) or upgrades the metadata endpoint to IMDSv2 (enforcing a session-oriented PUT negotiation token exchange).

### 4. Man-in-the-Cloud Lab (`man_in_the_cloud_lab.py`)
- **Vulnerability**: Persistent local storage of OAuth refresh tokens in cloud synchronization client databases.
- **Vulnerable Run**: The script writes a mock SQLite/JSON database containing active OAuth refresh tokens, harvests this token file using a simulated malware agent, and injects it into a rogue sync client. The rogue client connects to the storage provider, bypassing username, password, and MFA, and synchronizes the corporate repository.
- **Remediation**: Enables Token Binding policies (TPM validation), ensuring tokens only authenticate when presented by the authorized client's physical hardware.
