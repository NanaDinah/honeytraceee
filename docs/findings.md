# Findings

Results from the HoneyTrace honeypot. Figures are aggregated; raw logs are not published.

## Collection summary

| Metric | Value |
|---|---|
| Honeypot exposed to the internet | 2026-10-08 |
| Report period | TBD |
| Total connections | TBD |
| Unique source IPs | TBD |
| Countries observed | TBD |
| Failed login attempts | TBD |
| Successful (fake) logins | TBD |
| Commands executed | TBD |
| Files downloaded or uploaded | TBD |

*Own test sessions are excluded from every figure.*

## Early observations

- Unsolicited connections arrived within hours of exposing port 22
- Some scanners sent non-SSH traffic (for example an HTTP request) to the SSH port
- Some connections opened and closed within milliseconds, consistent with port probing

## Credentials

Most common usernames and passwords tried.

| Rank | Username | Count |
|---|---|---|
| 1 | TBD | TBD |

| Rank | Password | Count |
|---|---|---|
| 1 | TBD | TBD |

## Commands run after login

What attackers did once they got into the fake shell.

| Command pattern | Count | Likely purpose |
|---|---|---|
| TBD | TBD | TBD |

## Top sources

| Country / network | Connections |
|---|---|
| TBD | TBD |

## Detection rules

| Rule | Logic | MITRE ATT&CK | Hits |
|---|---|---|---|
| Brute-force burst | N failed logins from one IP within a time window | T1110 Brute Force | TBD |

## Timeline

*Charts of connections per day and per hour will be added here.*

## Conclusions

*To be written once enough data has been collected.*

## Limitations

- A single honeypot in one region gives a narrow view of internet-wide activity
- Many attackers are automated and do not reflect targeted threats
- Cowrie emulates a shell, so some attacker behavior is cut short