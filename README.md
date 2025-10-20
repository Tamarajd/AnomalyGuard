🤖 AnomalyGuard
===============

This is a **Clarity smart contract** designed for **AI-Powered Transaction Anomaly Detection**. It simulates the behavior of an AI analysis engine by implementing a multi-factor, threshold-based risk scoring system to monitor user transaction patterns and flag suspicious activities in real-time. This contract is intended to be integrated into a larger DeFi or financial application to provide an initial, on-chain layer of security and compliance monitoring.

* * * * *

🌟 Features
-----------

-   **Multi-Factor Risk Scoring:** Calculates a weighted risk score (0-100) based on three primary anomaly indicators:

    -   **Velocity Anomaly:** High frequency of transactions within a recent block window.

    -   **Amount Anomaly:** Significant deviation from the account's historical average transaction amount.

    -   **Frequency Anomaly:** Transactions occurring very rapidly (e.g., within 1 block of the last one).

-   **Threshold-Based Detection:** Flags a transaction as an anomaly if the calculated risk score exceeds a configurable `risk-score-threshold`.

-   **Historical Tracking:** Maintains on-chain statistics for each monitored account, including `total-transactions`, `total-volume`, and `average-amount`.

-   **Severity Levels:** Assigns a severity level (Low, Medium, High, Critical) to recorded anomalies based on the final risk score.

-   **Account Freezing:** Allows the contract owner to manually freeze and unfreeze accounts flagged as suspicious, preventing further activity via the contract.

-   **Configurable Parameters:** Allows the contract owner to dynamically adjust the core detection thresholds (`velocity-threshold`, `amount-deviation-threshold`, `risk-score-threshold`) to fine-tune the system's sensitivity.

-   **Audit Trail:** Stores detailed records of all detected anomalies for compliance and manual review.

* * * * *

🏗️ Contract Structure
----------------------

The contract is written in **Clarity**, a decidable language for smart contracts on the Stacks blockchain.

### Data Storage

| **Map/Variable** | **Type** | **Description** |
| --- | --- | --- |
| `account-stats` (Map) | `principal` $\to$ `{...}` | Stores comprehensive historical and current statistics for each account. |
| `anomaly-records` (Map) | `{account: principal, transaction-id: uint}` $\to$ `{...}` | Detailed record of every detected anomalous transaction. |
| `velocity-threshold` (Var) | `uint` | Max transactions allowed in the detection window before triggering a velocity anomaly. |
| `amount-deviation-threshold` (Var) | `uint` | Percentage deviation from average transaction amount to trigger an anomaly. |
| `risk-score-threshold` (Var) | `uint` | Minimum combined risk score (0-100) to flag a transaction as an anomaly. |
| `detection-window` (Var) | `uint` | Number of blocks to analyze for transaction velocity. |
| `transaction-counter` (Var) | `uint` | A global counter used to generate unique IDs for anomaly records. |

* * * * *

🚀 Public Functions (Main Interface)
------------------------------------

These are the functions that alter the contract's state or perform the core logic.

| **Function** | **Type** | **Description** |
| --- | --- | --- |
| `(analyze-transaction (account principal) (amount uint))` | Public | **CORE LOGIC.** Analyzes a new transaction, calculates the risk score, records any anomaly, updates account stats, and asserts that the account is not frozen. |
| `(update-thresholds (new-velocity uint) (new-deviation uint) (new-risk uint))` | Public (Owner-Only) | Sets the core detection parameters for velocity, amount deviation, and the overall risk score threshold. |
| `(set-account-freeze (account principal) (freeze bool))` | Public (Owner-Only) | Manually **freezes or unfreezes** a suspicious account based on owner discretion. |
| `(resolve-anomaly (account principal) (tx-id uint))` | Public (Owner-Only) | Marks a previously recorded anomaly in `anomaly-records` as resolved for audit purposes. |

* * * * *

🔎 Read-Only Functions (Inspection)
-----------------------------------

These functions do not alter the contract's state and are used for external monitoring, auditing, and retrieving account data.

| **Function** | **Type** | **Description** |
| --- | --- | --- |
| `(get-account-stats (account principal))` | Read-Only | Retrieves the latest statistics for a given account, including total transactions, average amount, and current risk score. Returns default stats if the account is new. |
| `(get-anomaly-record (account principal) (tx-id uint))` | Read-Only | Retrieves a specific anomaly record by the account and the unique transaction ID. |
| `(get-velocity-threshold)` | Read-Only (Implied from code structure) | Returns the current value of the `velocity-threshold` data variable. |
| `(get-risk-score-threshold)` | Read-Only (Implied from code structure) | Returns the current value of the `risk-score-threshold` data variable. |
| `(get-total-anomalies-detected)` | Read-Only (Implied from code structure) | Returns the total count of anomalies recorded since contract deployment. |

* * * * *

🛠️ Usage and Integration
-------------------------

The primary integration point is the `analyze-transaction` function. Any financial contract (e.g., a token transfer, swap, or loan execution) should call this function **before** completing the transaction.

### Example Integration Flow

1.  User initiates a financial transaction (e.g., `(ft-transfer u100)`).

2.  The financial contract internally calls `(contract-name.analyze-transaction tx-sender u100)`.

3.  `analyze-transaction` performs checks:

    -   **If the account is frozen:** The function will `asserts!` and return `err-account-frozen`, blocking the financial transaction.

    -   **If an anomaly is detected:**

        -   The transaction completes successfully (it is not blocked by default, only flagged for review).

        -   A detailed record is added to `anomaly-records`.

        -   The function returns the anomaly details (risk score, severity).

    -   **If no anomaly is detected:**

        -   The transaction completes successfully.

        -   The function returns the analysis data.

4.  The financial contract then proceeds with the fund transfer or asset interaction.

### Anomaly Score Calculation Detail

The `calculate-risk-score` private function implements the following weighted average:

$$\text{Risk Score} = 0.40 \times \text{Velocity Score} + 0.40 \times \text{Amount Score} + 0.20 \times \text{Frequency Score}$$

| **Factor** | **Weight** | **Score Logic Summary** |
| --- | --- | --- |
| **Velocity** | 40% | Measures transaction rate in the `detection-window`. Score increases if rate exceeds `velocity-threshold`. |
| **Amount** | 40% | Measures the percentage deviation from the account's historical average amount. |
| **Frequency** | 20% | A high score is assigned for extremely rapid, back-to-back transactions (within 2 blocks). |

* * * * *

🛡️ Error Codes
---------------

| **Error Code** | **Constant** | **Description** |
| --- | --- | --- |
| `u100` | `err-owner-only` | The function can only be called by the contract owner. |
| `u101` | `err-invalid-amount` | The transaction amount must be greater than zero. |
| `u102` | `err-account-frozen` | The transaction is blocked because the account has been manually frozen. |
| `u104` | `err-invalid-parameters` | One or more input parameters are invalid. |
| `u105` | `err-not-found` | Could not find the requested account stats or anomaly record. |

* * * * *

📝 MIT License
--------------

Copyright (c) 2025 AnomalyGuard

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

* * * * *

🤝 Contribution
---------------

We welcome contributions! If you have suggestions for new anomaly factors, improvements to the risk-scoring algorithm, or bug fixes, please follow these steps:

1.  Fork the repository.

2.  Create a new branch (`git checkout -b feature/AmazingFeature`).

3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).

4.  Push to the branch (`git push origin feature/AmazingFeature`).

5.  Open a Pull Request.

Please ensure all new code adheres to the existing Clarity style and includes appropriate comments.
