;; Decentralized Trust Network Protocol Smart Contract
;;
;; A cryptoeconomic identity verification system that creates trusted digital identities
;; through stake-weighted peer validation and time-based reputation scoring, designed
;; to prevent malicious actors from creating multiple fake identities in decentralized networks.

;; Network configuration variables
(define-data-var network-controller principal tx-sender)
(define-data-var required-economic-bond uint u1000000)
(define-data-var mandatory-peer-confirmations uint u3)
(define-data-var confirmation-waiting-period uint u144)
(define-data-var daily-trust-degradation uint u10)
(define-data-var credential-validity-duration uint u4320)

;; Error constants
(define-constant ERR-ACCESS-DENIED u1)
(define-constant ERR-VALIDATION-ALREADY-EXISTS u2)
(define-constant ERR-BOND-AMOUNT-INSUFFICIENT u3)
(define-constant ERR-TIME-LOCK-STILL-ACTIVE u4)
(define-constant ERR-SELF-VALIDATION-NOT-ALLOWED u5)
(define-constant ERR-IDENTITY-BLOCKED u6)
(define-constant ERR-TRUST-SCORE-TOO-LOW u7)
(define-constant ERR-CREDENTIAL-CHECK-FAILED u8)
(define-constant ERR-PARAMETER-INVALID u9)
(define-constant ERR-COMPUTATION-OVERFLOW u10)
(define-constant ERR-PRINCIPAL-INVALID u11)
(define-constant ERR-TEXT-INPUT-INVALID u12)

;; System constants for trust calculations
(define-constant max-possible-trust-points u1000)
(define-constant min-whistleblower-trust-level u500)
(define-constant trust-calculation-denominator u100)
(define-constant economic-bond-multiplier u30)
(define-constant peer-validation-multiplier u20)
(define-constant daily-block-count u144)
(define-constant validation-reward-factor u10)

;; Data maps for identity tracking
(define-map identity-economic-bonds
  { identity-holder: principal }
  {
    bonded-tokens: uint,
    bond-expiry-block: uint
  })

(define-map identity-peer-confirmations
  { identity-holder: principal }
  {
    confirmation-count: uint,
    most-recent-confirmation: uint
  })

(define-map identity-trust-metrics
  { identity-holder: principal }
  {
    trust-level: uint,
    last-trust-update: uint
  })

(define-map peer-validation-registry
  { confirming-peer: principal, confirmed-identity: principal }
  {
    confirmation-timestamp: uint,
    validation-power: uint
  })

(define-map blocked-identity-registry
  { blocked-identity: principal }
  {
    block-status: bool,
    block-justification: (string-utf8 100)
  })

;; Helper functions
(define-private (fetch-current-block-number)
  block-height)

(define-private (select-minimum-value (value-one uint) (value-two uint))
  (if (<= value-one value-two) value-one value-two))

(define-private (perform-safe-addition (addend-one uint) (addend-two uint))
  (let ((sum-value (+ addend-one addend-two)))
    (if (>= sum-value addend-one)
        (ok sum-value)
        (err ERR-COMPUTATION-OVERFLOW))))

(define-private (verify-identity-not-blocked (checking-identity principal))
  (is-some (map-get? blocked-identity-registry { blocked-identity: checking-identity })))

;; Calculate trust score based on economic bond, peer confirmations, and time decay
(define-read-only (determine-identity-trust-score (target-identity principal))
  (let
    (
      (bond-details (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                              (map-get? identity-economic-bonds { identity-holder: target-identity })))
      (confirmation-details (default-to { confirmation-count: u0, most-recent-confirmation: u0 }
                                   (map-get? identity-peer-confirmations { identity-holder: target-identity })))
      (trust-details (default-to { trust-level: u0, last-trust-update: u0 }
                                  (map-get? identity-trust-metrics { identity-holder: target-identity })))
      (present-block-number (fetch-current-block-number))
      (bond-strength-ratio (/ (get bonded-tokens bond-details) (var-get required-economic-bond)))
      (confirmation-reward-total (* (get confirmation-count confirmation-details) validation-reward-factor))
      (elapsed-blocks-since-update (if (> present-block-number (get last-trust-update trust-details))
                             (- present-block-number (get last-trust-update trust-details))
                             u0))
      ;; Apply time-based trust decay
      (trust-decay-percentage (select-minimum-value u100
                                      (* (var-get daily-trust-degradation)
                                         (/ elapsed-blocks-since-update daily-block-count))))
      (trust-retention-rate (- u100 trust-decay-percentage))
      (raw-trust-calculation (+ (* bond-strength-ratio economic-bond-multiplier)
                         (* confirmation-reward-total peer-validation-multiplier)))
      (time-adjusted-trust-value (/ (* raw-trust-calculation trust-retention-rate) trust-calculation-denominator))
    )
    (select-minimum-value max-possible-trust-points time-adjusted-trust-value)))

;; Update trust score in storage
(define-private (recalculate-identity-trust (target-identity principal))
  (let
    (
      (fresh-trust-score (determine-identity-trust-score target-identity))
      (present-block-number (fetch-current-block-number))
    )
    (map-set identity-trust-metrics
      { identity-holder: target-identity }
      { trust-level: fresh-trust-score, last-trust-update: present-block-number })
    fresh-trust-score))

;; Lock tokens as economic bond for identity verification
(define-public (commit-economic-bond (bond-token-amount uint) (lock-duration-blocks uint))
  (begin
    (asserts! (> bond-token-amount u0) (err ERR-PARAMETER-INVALID))
    (asserts! (> lock-duration-blocks u0) (err ERR-PARAMETER-INVALID))
    
    (let
      (
        (bond-creator tx-sender)
        (current-bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                  (map-get? identity-economic-bonds { identity-holder: bond-creator })))
        (present-block-number (fetch-current-block-number))
        (new-expiry-block (+ present-block-number lock-duration-blocks))
        (final-expiry-block (if (> (get bond-expiry-block current-bond-info) new-expiry-block)
                                (get bond-expiry-block current-bond-info)
                                new-expiry-block))
      )
      (begin
        (asserts! (not (verify-identity-not-blocked bond-creator)) (err ERR-IDENTITY-BLOCKED))
        
        ;; Transfer tokens to contract
        (try! (stx-transfer? bond-token-amount bond-creator (as-contract tx-sender)))
        
        (match (perform-safe-addition (get bonded-tokens current-bond-info) bond-token-amount)
          combined-bond-amount (begin
            (map-set identity-economic-bonds
              { identity-holder: bond-creator }
              {
                bonded-tokens: combined-bond-amount,
                bond-expiry-block: final-expiry-block
              })
            
            (recalculate-identity-trust bond-creator)
            (ok true))
          overflow-error (err overflow-error))))))

;; Withdraw bonded tokens after lock period expires
(define-public (retrieve-economic-bond (withdrawal-token-amount uint))
  (begin
    (asserts! (> withdrawal-token-amount u0) (err ERR-PARAMETER-INVALID))
    
    (let
      (
        (bond-owner tx-sender)
        (bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                 (map-get? identity-economic-bonds { identity-holder: bond-owner })))
        (present-block-number (fetch-current-block-number))
        (remaining-bond-tokens (- (get bonded-tokens bond-info) withdrawal-token-amount))
      )
      (begin
        (asserts! (not (verify-identity-not-blocked bond-owner)) (err ERR-IDENTITY-BLOCKED))
        (asserts! (>= present-block-number (get bond-expiry-block bond-info)) (err ERR-TIME-LOCK-STILL-ACTIVE))
        (asserts! (<= withdrawal-token-amount (get bonded-tokens bond-info)) (err ERR-BOND-AMOUNT-INSUFFICIENT))
        ;; Must maintain minimum bond or withdraw all
        (asserts! (or (is-eq remaining-bond-tokens u0)
                     (>= remaining-bond-tokens (var-get required-economic-bond)))
                 (err ERR-BOND-AMOUNT-INSUFFICIENT))
        
        (try! (as-contract (stx-transfer? withdrawal-token-amount (as-contract tx-sender) bond-owner)))
        
        (map-set identity-economic-bonds
          { identity-holder: bond-owner }
          {
            bonded-tokens: remaining-bond-tokens,
            bond-expiry-block: (if (is-eq remaining-bond-tokens u0) u0 (get bond-expiry-block bond-info))
          })
        
        (recalculate-identity-trust bond-owner)
        (ok true)))))

;; Provide peer validation for another identity (stake-weighted)
(define-public (provide-peer-validation (identity-to-validate principal))
  (begin
    (asserts! (not (is-eq identity-to-validate (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (not (verify-identity-not-blocked identity-to-validate)) (err ERR-IDENTITY-BLOCKED))
    
    (let
      (
        (validating-peer tx-sender)
        (validator-bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                   (map-get? identity-economic-bonds { identity-holder: validating-peer })))
        (validator-trust-score (determine-identity-trust-score validating-peer))
        (present-block-number (fetch-current-block-number))
        (target-confirmation-info (default-to { confirmation-count: u0, most-recent-confirmation: u0 }
                                        (map-get? identity-peer-confirmations { identity-holder: identity-to-validate })))
        (existing-validation-record (default-to { confirmation-timestamp: u0, validation-power: u0 }
                                        (map-get? peer-validation-registry
                                                 { confirming-peer: validating-peer, confirmed-identity: identity-to-validate })))
      )
      (begin
        (asserts! (not (is-eq validating-peer identity-to-validate)) (err ERR-SELF-VALIDATION-NOT-ALLOWED))
        (asserts! (>= (get bonded-tokens validator-bond-info) (var-get required-economic-bond)) (err ERR-BOND-AMOUNT-INSUFFICIENT))
        (asserts! (not (verify-identity-not-blocked validating-peer)) (err ERR-IDENTITY-BLOCKED))
        ;; Rate limiting: wait period between validations
        (asserts! (or (is-eq (get confirmation-timestamp existing-validation-record) u0)
                     (>= present-block-number (+ (get confirmation-timestamp existing-validation-record)
                                         (var-get confirmation-waiting-period))))
                 (err ERR-TIME-LOCK-STILL-ACTIVE))
        
        (let
          ((validation-strength (/ validator-trust-score trust-calculation-denominator)))
          
          (map-set peer-validation-registry
            { confirming-peer: validating-peer, confirmed-identity: identity-to-validate }
            { confirmation-timestamp: present-block-number, validation-power: validation-strength })
          
          (match (perform-safe-addition (get confirmation-count target-confirmation-info) u1)
            incremented-confirmation-count (begin
              (map-set identity-peer-confirmations
                { identity-holder: identity-to-validate }
                { confirmation-count: incremented-confirmation-count, most-recent-confirmation: present-block-number })
              
              (recalculate-identity-trust identity-to-validate)
              (ok true))
            arithmetic-error (err arithmetic-error)))))))

;; Check if identity meets all credential requirements
(define-read-only (assess-identity-credentials (target-identity principal))
  (let
    (
      (confirmation-data (default-to { confirmation-count: u0, most-recent-confirmation: u0 }
                                   (map-get? identity-peer-confirmations { identity-holder: target-identity })))
      (bond-data (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                              (map-get? identity-economic-bonds { identity-holder: target-identity })))
      (present-block-number (fetch-current-block-number))
      (credential-freshness-threshold (if (>= present-block-number (var-get credential-validity-duration))
                            (- present-block-number (var-get credential-validity-duration))
                            u0))
      (meets-confirmation-requirements (>= (get confirmation-count confirmation-data) (var-get mandatory-peer-confirmations)))
      (meets-bond-requirements (>= (get bonded-tokens bond-data) (var-get required-economic-bond)))
      (has-recent-network-activity (>= (get most-recent-confirmation confirmation-data) credential-freshness-threshold))
      (identity-not-restricted (not (verify-identity-not-blocked target-identity)))
    )
    (and meets-confirmation-requirements meets-bond-requirements has-recent-network-activity identity-not-restricted)))

;; Read-only functions for querying identity data
(define-read-only (fetch-identity-trust-level (target-identity principal))
  (determine-identity-trust-score target-identity))

(define-read-only (fetch-identity-bond-information (target-identity principal))
  (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
              (map-get? identity-economic-bonds { identity-holder: target-identity })))

(define-read-only (fetch-confirmation-requirements)
  (var-get mandatory-peer-confirmations))

(define-read-only (check-identity-restriction-status (target-identity principal))
  (if (verify-identity-not-blocked target-identity)
      (get block-status (unwrap-panic (map-get? blocked-identity-registry { blocked-identity: target-identity })))
      false))

(define-read-only (fetch-identity-confirmation-data (target-identity principal))
  (default-to { confirmation-count: u0, most-recent-confirmation: u0 }
              (map-get? identity-peer-confirmations { identity-holder: target-identity })))

;; Manually trigger trust score recalculation
(define-public (manually-refresh-trust-score (target-identity principal))
  (begin
    (asserts! (not (is-eq target-identity (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (not (verify-identity-not-blocked target-identity)) (err ERR-IDENTITY-BLOCKED))
    
    (ok (recalculate-identity-trust target-identity))))

;; Admin functions (network controller only)
(define-public (adjust-confirmation-requirements (updated-confirmation-threshold uint))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (> updated-confirmation-threshold u0) (err ERR-PARAMETER-INVALID))
    (var-set mandatory-peer-confirmations updated-confirmation-threshold)
    (ok true)))

(define-public (adjust-bond-requirements (updated-bond-minimum uint))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (> updated-bond-minimum u0) (err ERR-PARAMETER-INVALID))
    (var-set required-economic-bond updated-bond-minimum)
    (ok true)))

(define-public (adjust-trust-degradation-rate (updated-degradation-rate uint))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (<= updated-degradation-rate u100) (err ERR-PARAMETER-INVALID))
    (var-set daily-trust-degradation updated-degradation-rate)
    (ok true)))

;; Block/unblock identities (admin function)
(define-public (impose-identity-restriction (target-identity principal) (restriction-rationale (string-utf8 100)))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (not (is-eq target-identity (var-get network-controller))) (err ERR-PARAMETER-INVALID))
    (asserts! (not (is-eq target-identity (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (> (len restriction-rationale) u0) (err ERR-TEXT-INPUT-INVALID))
    
    (map-set blocked-identity-registry
      { blocked-identity: target-identity }
      { block-status: true, block-justification: restriction-rationale })
    (ok true)))

(define-public (lift-identity-restriction (target-identity principal))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (not (is-eq target-identity (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (verify-identity-not-blocked target-identity) (err ERR-PARAMETER-INVALID))
    
    (map-delete blocked-identity-registry { blocked-identity: target-identity })
    (ok true)))

;; Transfer network control to new admin
(define-public (delegate-network-control (successor-controller principal))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (not (is-eq successor-controller tx-sender)) (err ERR-PARAMETER-INVALID))
    (asserts! (not (is-eq successor-controller (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    
    (var-set network-controller successor-controller)
    (ok true)))

;; Report suspicious identities (requires high trust score)
(define-public (submit-fraud-alert (suspicious-identity principal) (fraud-evidence (string-utf8 500)))
  (begin
    (asserts! (not (is-eq suspicious-identity (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (> (len fraud-evidence) u0) (err ERR-TEXT-INPUT-INVALID))
    (asserts! (not (verify-identity-not-blocked suspicious-identity)) (err ERR-IDENTITY-BLOCKED))
    
    (let
      (
        (alert-submitter tx-sender)
        (submitter-bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                   (map-get? identity-economic-bonds { identity-holder: alert-submitter })))
        (submitter-trust-level (determine-identity-trust-score alert-submitter))
      )
      (begin
        (asserts! (not (verify-identity-not-blocked alert-submitter)) (err ERR-IDENTITY-BLOCKED))
        (asserts! (>= (get bonded-tokens submitter-bond-info) (var-get required-economic-bond)) (err ERR-BOND-AMOUNT-INSUFFICIENT))
        ;; Only high-trust identities can submit fraud alerts
        (asserts! (>= submitter-trust-level min-whistleblower-trust-level) (err ERR-TRUST-SCORE-TOO-LOW))
        
        (print {
          alert-category: "fraudulent-identity-report",
          reporting-identity: alert-submitter,
          flagged-identity: suspicious-identity,
          supporting-evidence: fraud-evidence,
          submission-block: (fetch-current-block-number)
        })
        (ok true)))))

;; Transfer bonded tokens between identities
(define-public (execute-bond-transfer (receiving-identity principal) (transfer-token-amount uint))
  (begin
    (asserts! (> transfer-token-amount u0) (err ERR-PARAMETER-INVALID))
    (asserts! (not (is-eq receiving-identity (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    (asserts! (not (verify-identity-not-blocked receiving-identity)) (err ERR-IDENTITY-BLOCKED))
    
    (let
      (
        (transferring-identity tx-sender)
        (sender-bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                 (map-get? identity-economic-bonds { identity-holder: transferring-identity })))
        (receiver-bond-info (default-to { bonded-tokens: u0, bond-expiry-block: u0 }
                                    (map-get? identity-economic-bonds { identity-holder: receiving-identity })))
        (sender-remaining-tokens (- (get bonded-tokens sender-bond-info) transfer-token-amount))
      )
      (begin
        (asserts! (not (verify-identity-not-blocked transferring-identity)) (err ERR-IDENTITY-BLOCKED))
        (asserts! (<= transfer-token-amount (get bonded-tokens sender-bond-info)) (err ERR-BOND-AMOUNT-INSUFFICIENT))
        ;; Must maintain minimum bond or transfer all
        (asserts! (or (is-eq sender-remaining-tokens u0)
                     (>= sender-remaining-tokens (var-get required-economic-bond)))
                 (err ERR-BOND-AMOUNT-INSUFFICIENT))
        
        (map-set identity-economic-bonds
          { identity-holder: transferring-identity }
          {
            bonded-tokens: sender-remaining-tokens,
            bond-expiry-block: (if (is-eq sender-remaining-tokens u0) u0 (get bond-expiry-block sender-bond-info))
          })
        
        (match (perform-safe-addition (get bonded-tokens receiver-bond-info) transfer-token-amount)
          updated-receiver-bond (begin
            (map-set identity-economic-bonds
              { identity-holder: receiving-identity }
              {
                bonded-tokens: updated-receiver-bond,
                bond-expiry-block: (if (> (get bond-expiry-block receiver-bond-info) (get bond-expiry-block sender-bond-info))
                                        (get bond-expiry-block receiver-bond-info)
                                        (get bond-expiry-block sender-bond-info))
              })
            
            ;; Update trust scores for both parties
            (recalculate-identity-trust transferring-identity)
            (recalculate-identity-trust receiving-identity)
            (ok true))
          arithmetic-error (err arithmetic-error))))))

;; Initialize network with first controller
(define-public (initialize-network-protocol (initial-network-controller principal))
  (begin
    (asserts! (is-eq tx-sender (var-get network-controller)) (err ERR-ACCESS-DENIED))
    (asserts! (not (is-eq initial-network-controller tx-sender)) (err ERR-PARAMETER-INVALID))
    (asserts! (not (is-eq initial-network-controller (as-contract tx-sender))) (err ERR-PRINCIPAL-INVALID))
    
    (var-set network-controller initial-network-controller)
    (ok true)))