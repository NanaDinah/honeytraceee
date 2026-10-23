# Findings

Results from the HoneyTrace honeypot. Figures are aggregated; raw logs and attacker IP addresses are not published. My own test sessions (three source addresses) are excluded from every number.

*Data as of 23 October 2026, 07:54 UTC.*

## Collection summary

| Metric | Value |
|---|---|
| Honeypot exposed to the internet | 8 October 2026 |
| Period analysed | 8 Oct 08:59 UTC to 23 Oct 07:54 UTC (about 15 days) |
| Events recorded | 4,144 |
| Sessions (connections) | 1,392 |
| Unique source IPs | 774 |
| Countries observed | 83 |
| Logins accepted by the fake server | 133 |
| Commands typed | 160 |
| File transfers (uploads and downloads) | 30 |
| Detection alerts | 254 |

Cowrie accepts almost any credentials by default, so nearly every login attempt "succeeds". The numbers therefore show which usernames and passwords bots try, not which ones would work on a real server.

## Where the traffic came from

Sessions by country, top ten:

| Rank | Country | Sessions |
|---|---|---|
| 1 | United States | 258 |
| 2 | Argentina | 153 |
| 3 | Ukraine | 104 |
| 4 | United Kingdom | 78 |
| 5 | Russia | 71 |
| 6 | China | 44 |
| 7 | Belgium | 41 |
| 8 | Chile | 37 |
| 9 | Netherlands | 35 |
| 10 | Côte d’Ivoire | 31 |

The ten countries above account for about 61% of all sessions; the rest came from 73 other countries. Country comes from a free IP-to-country database and shows where an address is registered, not where the person operating it sits. Many scanners run from rented servers or proxies, so these results describe hosting locations more than attackers.

## Behaviour clusters

### 1. Repeating fingerprint bot
One source made the most connections of any visitor (45). Over several hours on 11 October it logged in repeatedly and ran the same system-fingerprinting command roughly every two minutes, cycling between the usernames `root` and `ubuntu`. Its connection count has not grown since 13 October, so that burst appears to have been a one-off. The same fingerprint command (`uname -s -v -n -r -m`) was also the first thing my very first outside visitor ran, so it looks like a common bot routine. It was typed 77 times in total, in two forms: with and without a `/bin/./` prefix.

### 2. Shared dropper campaign
Several sources ran an identical long shell command (a PATH export followed by a chain of `uname` fallbacks), created a small script with `printf`, made it executable with `chmod +x`, and fetched a file. The file hash `af77b643...` has now appeared **15 times**, up from 10 on 13 October. The script-staging rule (HT-004) now fires for **9 sources**, up from 3, so more addresses are running the same routine. Identical payload and command text across many addresses points to shared tooling, though I cannot prove a single operator from the logs.

### 3. File transfers
Thirty file transfers were recorded. Early on, uploads of a file named `sshd` arrived exactly five minutes after a root login, from different sources, suggesting a shared script; some of those were empty files (the SHA-256 of zero bytes, now seen 3 times). Since 13 October, six new file hashes have appeared that I have not yet analysed. A file named like the real SSH daemon is consistent with an attempt to replace or disguise a system binary.

### 4. Probing and honeypot checks
A few visitors ran unusual commands: a RouterOS-style `/ip cloud print`, `ifconfig`, `echo Hi | cat -n`, and a `locate` with a random string, each a handful of times. These look like checks for network devices or tests of whether the shell is real.

### 5. Default-credential spraying
51 different sources logged in using well-known default or cloud-image account names (`root`, `admin`, `ubuntu`, `azureuser`, `debian`, `ftpuser`). Many other usernames appeared only once or twice, which looks like bots working through long username lists.

## Credentials

| Rank | Username | Count |
|---|---|---|
| 1 | root | 56 |
| 2 | admin | 11 |
| 3 | ubuntu | 6 |
| 4 | sol | 4 |
| 5 | ansible | 3 |

| Rank | Password | Count |
|---|---|---|
| 1 | 123456 | 14 |
| 2 | ubuntu | 13 |
| 3 | admin | 12 |
| 4 | 111111 | 4 |
| 5 | 123 | 4 |

## Commands run after login

| Command | Count | Likely purpose |
|---|---|---|
| `/bin/./uname -s -v -n -r -m` | 60 | Fingerprint the system |
| `uname -s -v -n -r -m` | 17 | Fingerprint the system |
| Script created with `printf` and made executable | 15 | Stage a script |
| `export PATH=... uname=$(uname ...)` chain | 15 | Fingerprint, then fetch a file |
| `uname -a` | 9 | Fingerprint the system |
| `/ip cloud print` | 3 | Probe for a router OS |
| `cat /proc/cpuinfo` | 3 | Check hardware |
| `ifconfig` | 3 | Check network configuration |

## File hashes (indicators)

Files are never opened or executed; they are identified by hash only.

| SHA-256 | Seen | Note |
|---|---|---|
| `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32` | 15 | Shared across several sources |
| `94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00` | 4 | New since 13 Oct |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 3 | Empty file |
| `130b71d63afd3eb728ff89a80ab09a23c9f4e6c0c17854c045f196925f4ac8e5` | 1 | New since 13 Oct |
| `595bae8df38a54d1ed9c253a6537d3901e96fd5c99e2324e7e74f1b456d41fca` | 1 | Uploaded as `sshd` |
| `6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b` | 1 | New since 13 Oct |
| `abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023` | 1 | Uploaded as `sshd` |
| `b593f27ce966f5458a17e8dbba27fbed939019588fc3b4d75df1f509434b7ba4` | 1 | New since 13 Oct |
| `d16bffbd3ba31504aea1fc01e66e29ad5927830ea5e2cc49369e82a7c68ec5c0` | 1 | New since 13 Oct |
| `fcbc6f221902f90575f945fec23880a757f8f9ae921c19d2b29858cf15de2a63` | 1 | New since 13 Oct |

Reputation lookups: *not yet checked on a public service.*

## Detection rules

| Rule | Logic | MITRE ATT&CK | Alerts | Source IPs |
|---|---|---|---|---|
| HT-001 | Commands that fingerprint the system | T1082 System Information Discovery | 104 | 28 |
| HT-002 | Login using a well-known default account name | T1078.001 Valid Accounts: Default Accounts | 80 | 51 |
| HT-003 | File uploaded or downloaded during a session | T1105 Ingress Tool Transfer | 30 | 20 |
| HT-004 | File made executable (`chmod +x`, `chmod 777`) | T1222.002 File and Directory Permissions Modification: Linux and Mac | 34 | 9 |
| HT-005 | Network configuration discovery (`ifconfig`, `ip addr`, RouterOS probes) | T1016 System Network Configuration Discovery | 6 | 3 |

Alert counts are inflated by repeating bots, so the source-IP column is the better measure of how many separate visitors each rule caught.

## Conclusions

- A new SSH server on the public internet is found and probed within hours, and traffic comes from every corner of the world: 774 distinct addresses from 83 countries in 15 days.
- Almost all of it is automated. Most visitors fingerprint the machine first, then decide whether to deploy something.
- Several unrelated sources use the same payloads and commands, so shared tooling is common, and one dropper routine has spread to more addresses over time.
- The most tried credentials are the obvious ones (`root`, `123456`, `admin`, `ubuntu`), which is why default accounts and weak passwords are the first thing to remove from any server.
- Detection rules work best when built from what attackers do after login, because login attempts alone say little against a honeypot that accepts them.

## Limitations

- A single honeypot in one region gives a narrow view of internet-wide activity
- Many attackers are automated and do not reflect targeted threats
- Cowrie emulates a shell, so some attacker behaviour is cut short
- Because Cowrie accepts most logins, credential statistics describe attempts, not working passwords
- Country data is approximate and reflects where an address is hosted, not where its operator is
- Each IP address is counted separately, so one operator using many addresses is counted many times