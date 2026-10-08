# Threat Model: HoneyTrace

## 1. Purpose

HoneyTrace deliberately exposes a fake SSH service to the public internet to observe attacker behavior. Because the system is *designed* to be attacked, this document describes what is exposed, what could go wrong, and the controls used to keep the risk contained.

## 2. Assets

| Asset | Why it matters |
|---|---|
| AWS account and sign-in | Compromise could lead to cost abuse or data loss |
| Honeypot instance | If broken out of, it could be used to attack others |
| Collected logs | Contain attacker IPs, credentials and commands; must stay intact |
| Admin SSH access | The only real way into the host |
| My personal network and devices | Must never be reachable from the honeypot |

## 3. Design Summary

| Component | Detail |
|---|---|
| Host | Single EC2 instance (Ubuntu 24.04, t3.micro) in an otherwise empty AWS account |
| Honeypot | Cowrie, run by an unprivileged `cowrie` user with no sudo and no password |
| Public SSH (port 22) | Redirected by iptables to Cowrie on port 2222 |
| Real admin SSH | Moved to a non-standard port, key-only, allowed from my IP only |
| Instance role | None. No AWS credentials exist on the host |
| Log transfer | Pulled from the laptop over the admin SSH port (rsync); nothing is pushed out from the host |
| Analysis | Java 21 application on my laptop, reading local copies of the logs |

## 4. Trust Boundaries

```
[ Internet ] --> (port 22 redirected to 2222) --> [ Cowrie (unprivileged user) ]
                                                        |
                                              [ Honeypot VM, assumed compromisable ]
                                                        ^
[ My IP only ] --> (admin port, key-only) --------------+
                                                        |
                         (rsync pull over admin SSH)    v
                                              [ My laptop: Java analysis ]
```

- Untrusted: everything from the internet and everything inside Cowrie's fake shell
- Semi-trusted: the honeypot VM (assumed compromisable)
- Trusted: my laptop and my AWS sign-in

## 5. Threats and Mitigations

| # | Threat | Impact | Mitigation |
|---|---|---|---|
| T1 | Attacker escapes the fake shell and gets a real shell on the VM | Host used for attacks or pivoting | Cowrie runs as an unprivileged user with no sudo; no sensitive data or credentials on the VM |
| T2 | Compromised VM used to attack other systems | Legal and reputational harm | Outbound security group rules allow only HTTPS, HTTP and DNS; no outbound SSH, mail or other protocols |
| T3 | Attacker steals AWS credentials from the VM | Account takeover | No instance role and no access keys on disk, so there is nothing to steal |
| T4 | Real admin SSH brute-forced or exploited | Full host takeover | Non-standard port, key-only authentication, source restricted to my IP, root login disabled |
| T5 | Malicious data in logs attacks my analysis code | Code injection or parser crash | All log fields treated as untrusted; strict typed parsing with Jackson; malformed lines skipped; no log content is ever executed; parameterized SQL when storage is added |
| T6 | Attacker uploads malware to the honeypot | Malware handling risk | Cowrie stores downloads in a quarantine folder; downloads are never executed and are analyzed by hash only |
| T7 | Resource exhaustion or unexpected cost | AWS bill | Free plan with credit balance; small instance; billing page checked daily |
| T8 | Secrets leaked in the public repo | Account or host compromise | `.gitignore` rules for keys, logs and Cowrie runtime files; tracked file list reviewed before each push |
| T9 | Log tampering or loss if the host is compromised or wiped | Corrupted or lost findings | Logs copied to my laptop regularly, so a compromised host cannot rewrite the copies already pulled |
| T10 | Personal data exposure in published findings | Privacy issues | Publish aggregated statistics only; raw logs stay out of the repository; my own IP excluded from analysis |
| T11 | Lockout from my own host after a configuration change | Lost access during setup | Admin port tested from a second session before the first was closed; security group rule edited as a fallback |

## 6. Isolation Design

- The AWS account is new and contains no other resources, so the default VPC holds only the honeypot
- Security group inbound: port 22 open to the internet (the honeypot), the admin port open to my IP only
- Security group outbound: HTTPS, HTTP and DNS only
- No VPC peering, VPN or connection to any other network
- No AWS credentials or instance role on the host

## 7. Out of Scope

- Attacking, scanning or "hacking back" any attacker
- Running any downloaded malware
- Collecting data from any system other than the honeypot

## 8. Legal and Ethical Notes

- The honeypot only receives traffic sent to it; it never initiates attacks
- Captured data is used for defensive research and education
- Follow AWS's Acceptable Use Policy
- Published results are aggregated and do not include sensitive personal data

## 9. Residual Risks

Even with these controls, some risk remains: a vulnerability in the honeypot software or the OS, a misconfiguration on my part, or a compromise of the personal sign-in used for the AWS account. Reviewing logs regularly, keeping the host patched, and protecting the sign-in with two-step verification reduce this, and the isolated design limits the damage if it happens.

## 10. Review Log

| Date | Change |
|---|---|
| 2026-10-08 | Initial version, updated to match the deployed design (no instance role, logs pulled over SSH) |