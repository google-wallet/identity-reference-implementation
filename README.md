# Google Wallet Identity Reference Implementations

This repository serves as a central hub for reference implementations of the **Google Wallet Identity** ecosystem. It provides end-to-end code examples for different identity partners - including **Issuers** and **Verifiers (Relying Parties)** - to help developers integrate digital credentials using standard protocols.

> **Disclaimer**: This is Not an officially supported Google product. This project is intended for **demonstration purposes only** and is not intended for use in a production environment. This project is **not** eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

---

## 🌐 Ecosystem Overview

The Identity ecosystem involves three primary actors. This repository provides the technical scaffolding for the **Issuer** and **Verifier** roles to interact with the **User's Wallet**.

1.  **Issuer**: The entity that signs and issues digital credentials (e.g., a Mobile Driver's License or Health Card) to the user's wallet.
2.  **User/Wallet**: The individual holding the digital credential in Google Wallet on an Android device.
3.  **Verifier (Relying Party)**: The entity requesting and verifying the credential to provide a service (e.g., age verification or identity boarding).

---

## 📂 Repository Structure

Each directory below contains a standalone project with its own specific setup instructions, prerequisites, and configuration steps.

| Component | Path | Description | Tech Stack |
| :--- | :--- | :--- | :--- |
| **Verifiers** | [`/verifiers-reference-implementation`](./verifiers-reference-implementation) | Logic for requesting, decrypting, and verifying credentials via OpenID4VP. | Python, Android |

---

## 🛠 Featured Implementations

### [Verifiers (Relying Party)](./verifiers-reference-implementation)
The Verifier implementation demonstrates how a service provider can request digital identity attributes from a user's Google Wallet.

* **Android (Client):** Implements `WalletCredentialHandler` and `ServerRequestHandler` to bridge the gap between your app and the system wallet.
* **Python (Server):** A Flask-based server that handles the `openid4vp` protocol and verifies credential signatures.
* **Zero-Knowledge Proofs (ZKP):** Includes endpoints to demonstrate how to verify proofs without sharing raw PII.

---

## 🚀 Getting Started

To get started with an implementation, navigate to the specific partner folder and follow the instructions in its local README.

1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/](https://github.com/)<your-org>/identity-reference-implementation.git
    cd identity-reference-implementation
    ```

2.  **Choose your implementation**:
    ```bash
    # Go to the Verifier reference
    cd verifiers-reference-implementation
    ```

3.  **Follow local setup**: 
    Follow the Python and Android setup instructions found in that directory.

---

## 📄 License

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for more details.

---
