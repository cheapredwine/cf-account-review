# Compliance Framework Mapping

This document maps cf-account-review findings to compliance framework controls.
The mapping is advisory only — it identifies which findings **support evidence**
for controls, not which findings **satisfy** them. Compliance attestation requires
independent audit.

## Frameworks covered

- **SOC 2** — Trust Service Criteria (TSC):
  - CC = Common Criteria (all trust services)
  - A = Availability
  - C = Confidentiality
  - S = Security (not separate in 2017 criteria; subsumed by CC)
- **PCI DSS 4.0** — Payment Card Industry Data Security Standard

## Mapping principles

1. A check maps to a control when its **pass verdict** provides evidence that
   supports the control's objective.
2. A check may map to multiple controls (e.g., encryption supports both SOC 2
   confidentiality and PCI DSS requirement 4).
3. **Absence of a mapping does not mean the check is compliance-irrelevant** —
   it may support defense-in-depth, best practices, or vendor-specific guidance.

## Control reference

### SOC 2 TSC (2017 criteria)

- **CC6.1** — Logical and physical access controls restrict access to system resources
- **CC6.6** — Transmission of sensitive information is protected
- **CC6.7** — Detection and monitoring processes identify anomalies
- **CC7.1** — Detection processes identify security events
- **CC7.2** — Monitoring activities detect security incidents
- **CC8.1** — Change management processes ensure authorized changes

### PCI DSS 4.0

- **Req 2.2** — System configurations maintained securely
- **Req 4.2** — Strong cryptography protects cardholder data during transmission
- **Req 6.4** — Vulnerabilities identified and addressed
- **Req 8.2** — User identification and authentication managed
- **Req 10.2** — Audit logs capture security-relevant events
- **Req 11.3** — External and internal vulnerabilities regularly identified

## Check-to-control mapping

See `findings/checks.yaml` — each check carries a `compliance: []` field listing
applicable framework controls. Common mappings:

| Domain | Controls typically mapped |
|--------|---------------------------|
| SSL/TLS | SOC 2 CC6.6, CC6.7; PCI DSS 4.2 |
| WAF | SOC 2 CC7.1, CC7.2; PCI DSS 6.4, 11.3 |
| Account hygiene (MFA, API tokens) | SOC 2 CC6.1; PCI DSS 8.2 |
| DNS (DNSSEC, CAA) | SOC 2 CC6.6, CC6.7 |
| Zero Trust Access | SOC 2 CC6.1; PCI DSS 8.2 |
| Bots / rate limiting | SOC 2 CC7.1; PCI DSS 6.4 |
| Workers (route coverage) | SOC 2 CC8.1 |
| DDoS / origin security | SOC 2 A1.2 (availability); PCI DSS 6.4 |
