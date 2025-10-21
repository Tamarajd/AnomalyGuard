;; AI-Powered Transaction Anomaly Detection Smart Contract
;; This contract monitors transaction patterns and detects anomalies using threshold-based
;; analysis simulating AI behavior. It tracks user transaction history, calculates risk scores,
;; and flags suspicious activities based on deviation from normal patterns.

;; constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-invalid-amount (err u101))
(define-constant err-account-frozen (err u102))
(define-constant err-threshold-exceeded (err u103))
(define-constant err-invalid-parameters (err u104))
(define-constant err-not-found (err u105))

;; Anomaly severity levels
(define-constant severity-low u1)
(define-constant severity-medium u2)
(define-constant severity-high u3)
(define-constant severity-critical u4)

;; Default thresholds for anomaly detection
(define-constant default-velocity-threshold u5) ;; max transactions per block
(define-constant default-amount-deviation u200) ;; 200% deviation from average
(define-constant default-risk-threshold u75) ;; risk score threshold (0-100)

;; data maps and vars

;; Tracks transaction history for each account
(define-map account-stats
    principal
    {
        total-transactions: uint,
        total-volume: uint,
        average-amount: uint,
        last-transaction-block: uint,
        transactions-in-window: uint,
        risk-score: uint,
        is-frozen: bool
    }
)

;; Records individual anomalous transactions
(define-map anomaly-records
    {account: principal, transaction-id: uint}
    {
        amount: uint,
        block-height: uint,
        severity: uint,
        reason: (string-ascii 100),
        resolved: bool
    }
)

;; Configurable detection thresholds (modifiable by owner)
(define-data-var velocity-threshold uint default-velocity-threshold)
(define-data-var amount-deviation-threshold uint default-amount-deviation)
(define-data-var risk-score-threshold uint default-risk-threshold)
(define-data-var detection-window uint u10) ;; blocks to analyze for velocity

;; Global statistics
(define-data-var total-anomalies-detected uint u0)
(define-data-var total-accounts-monitored uint u0)

;; Transaction counter for unique IDs
(define-data-var transaction-counter uint u0)

;; private functions

;; Return the minimum of two numbers
(define-private (min (a uint) (b uint))
    (if (<= a b) a b)
)

;; Return the maximum of two numbers
(define-private (max (a uint) (b uint))
    (if (>= a b) a b)
)

;; Calculate the absolute difference between two numbers
(define-private (abs-diff (a uint) (b uint))
    (if (>= a b)
        (- a b)
        (- b a)
    )
)

;; Calculate percentage deviation from average
(define-private (calculate-deviation (amount uint) (average uint))
    (if (is-eq average u0)
        u0
        (/ (* (abs-diff amount average) u100) average)
    )
)

;; Determine severity level based on risk score
(define-private (get-severity-level (risk-score uint))
    (if (>= risk-score u90)
        severity-critical
        (if (>= risk-score u75)
            severity-high
            (if (>= risk-score u50)
                severity-medium
                severity-low
            )
        )
    )
)

;; Calculate risk score based on multiple factors (0-100 scale)
(define-private (calculate-risk-score 
    (velocity-score uint) 
    (amount-score uint) 
    (frequency-score uint))
    (let
        (
            (weighted-velocity (/ (* velocity-score u40) u100))
            (weighted-amount (/ (* amount-score u40) u100))
            (weighted-frequency (/ (* frequency-score u20) u100))
        )
        (+ weighted-velocity (+ weighted-amount weighted-frequency))
    )
)

;; Update account statistics after transaction
(define-private (update-account-stats 
    (account principal) 
    (amount uint) 
    (new-risk-score uint))
    (let
        (
            (current-stats (default-to
                {
                    total-transactions: u0,
                    total-volume: u0,
                    average-amount: u0,
                    last-transaction-block: u0,
                    transactions-in-window: u0,
                    risk-score: u0,
                    is-frozen: false
                }
                (map-get? account-stats account)
            ))
            (new-total-txs (+ (get total-transactions current-stats) u1))
            (new-total-volume (+ (get total-volume current-stats) amount))
            (new-average (/ new-total-volume new-total-txs))
        )
        (map-set account-stats account
            {
                total-transactions: new-total-txs,
                total-volume: new-total-volume,
                average-amount: new-average,
                last-transaction-block: block-height,
                transactions-in-window: u1,
                risk-score: new-risk-score,
                is-frozen: (get is-frozen current-stats)
            }
        )
    )
)

;; public functions

;; Initialize or retrieve account statistics
(define-read-only (get-account-stats (account principal))
    (ok (default-to
        {
            total-transactions: u0,
            total-volume: u0,
            average-amount: u0,
            last-transaction-block: u0,
            transactions-in-window: u0,
            risk-score: u0,
            is-frozen: false
        }
        (map-get? account-stats account)
    ))
)

;; Retrieve anomaly record
(define-read-only (get-anomaly-record (account principal) (tx-id uint))
    (ok (map-get? anomaly-records {account: account, transaction-id: tx-id}))
)

;; Admin: Update detection thresholds
(define-public (update-thresholds 
    (new-velocity uint) 
    (new-deviation uint) 
    (new-risk uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (and (<= new-risk u100) (> new-deviation u0)) err-invalid-parameters)
        (var-set velocity-threshold new-velocity)
        (var-set amount-deviation-threshold new-deviation)
        (var-set risk-score-threshold new-risk)
        (ok true)
    )
)

;; Admin: Freeze/unfreeze suspicious account
(define-public (set-account-freeze (account principal) (freeze bool))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (let
            (
                (stats (unwrap! (get-account-stats account) err-not-found))
            )
            (map-set account-stats account
                (merge stats {is-frozen: freeze})
            )
            (ok true)
        )
    )
)

;; Admin: Mark anomaly as resolved
(define-public (resolve-anomaly (account principal) (tx-id uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (match (map-get? anomaly-records {account: account, transaction-id: tx-id})
            anomaly-data
                (begin
                    (map-set anomaly-records 
                        {account: account, transaction-id: tx-id}
                        (merge anomaly-data {resolved: true})
                    )
                    (ok true)
                )
            err-not-found
        )
    )
)

;; Core function: Analyze and record transaction with AI-powered anomaly detection
;; This function performs comprehensive analysis of incoming transactions by:
;; 1. Checking if the account is frozen
;; 2. Calculating velocity-based anomalies (transactions per time window)
;; 3. Detecting amount-based anomalies (deviation from historical average)
;; 4. Computing frequency anomalies (unusual transaction patterns)
;; 5. Generating an overall risk score using weighted factors
;; 6. Recording anomalies that exceed thresholds
;; 7. Updating account statistics for future analysis
(define-public (analyze-transaction (account principal) (amount uint))
    (begin
        (asserts! (> amount u0) err-invalid-amount)
        
        (let
            (
                ;; Retrieve or initialize account statistics
                (stats (unwrap! (get-account-stats account) err-invalid-parameters))
                (is-frozen (get is-frozen stats))
                (avg-amount (get average-amount stats))
                (last-block (get last-transaction-block stats))
                (txs-in-window (get transactions-in-window stats))
                
                ;; Calculate time-based metrics
                (blocks-since-last (if (> last-block u0) 
                    (- block-height last-block) 
                    u999))
                (is-in-window (< blocks-since-last (var-get detection-window)))
                (current-velocity (if is-in-window (+ txs-in-window u1) u1))
                
                ;; Calculate anomaly scores (0-100 scale)
                (velocity-anomaly (if (> current-velocity (var-get velocity-threshold))
                    (min u100 (* (- current-velocity (var-get velocity-threshold)) u20))
                    u0))
                
                (amount-deviation (calculate-deviation amount avg-amount))
                (amount-anomaly (if (> amount-deviation (var-get amount-deviation-threshold))
                    (min u100 (/ amount-deviation u3))
                    u0))
                
                (frequency-anomaly (if (and is-in-window (< blocks-since-last u2))
                    u80
                    u0))
                
                ;; Calculate overall risk score
                (risk-score (calculate-risk-score 
                    velocity-anomaly 
                    amount-anomaly 
                    frequency-anomaly))
                
                ;; Determine if this is an anomaly
                (is-anomaly (>= risk-score (var-get risk-score-threshold)))
                (severity (get-severity-level risk-score))
                (tx-id (var-get transaction-counter))
            )
            
            ;; Check if account is frozen
            (asserts! (not is-frozen) err-account-frozen)
            
            ;; Record anomaly if detected
            (if is-anomaly
                (begin
                    (map-set anomaly-records
                        {account: account, transaction-id: tx-id}
                        {
                            amount: amount,
                            block-height: block-height,
                            severity: severity,
                            reason: "AI-detected: Multi-factor risk threshold exceeded",
                            resolved: false
                        }
                    )
                    (var-set total-anomalies-detected 
                        (+ (var-get total-anomalies-detected) u1))
                )
                true
            )
            
            ;; Update account statistics
            (update-account-stats account amount risk-score)
            (var-set transaction-counter (+ tx-id u1))
            
            ;; Return analysis results
            (ok {
                transaction-id: tx-id,
                risk-score: risk-score,
                is-anomaly: is-anomaly,
                severity: severity,
                details: {
                    velocity-score: velocity-anomaly,
                    amount-score: amount-anomaly,
                    frequency-score: frequency-anomaly
                }
            })
        )
    )
)



