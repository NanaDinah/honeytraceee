# Findings

Results from the HoneyTrace honeypot. Figures are aggregated; raw logs and attacker IP addresses are not published. My own test sessions (three source addresses) are excluded from every number.

*Data as of 13 October 2026, 07:20 UTC.*

## Collection summary

| Metric | Value |
|---|---|
| Honeypot exposed to the internet | 8 October 2026 |
| Period analysed | 8 Oct 08:59 UTC to 13 Oct 07:20 UTC (about 5 days) |
| Events recorded | 1,647 |
| Sessions (connections) | 482 |
| Unique source IPs | 237 |
| Logins accepted by the fake server | 71 |
| Logins rejected | 3 |
| Commands typed | 99 |
| File downloads (wget/curl style) | 10 |
| File uploads (SFTP) | 4 |
| Detection alerts | 112 |
| Countries observed | TBD (GeoIP enrichment pending) |

Cowrie accepts almost any credentials by default, so nearly every attempt "succeeds". The numbers therefore show which usernames and passwords bots try, not which ones would work on a real server.

## Behaviour clusters

### 1. Repeating fingerprint bot
One source made the most connections of any visitor (45). Over several hours on 11 October it logged in repeatedly and ran the same system-fingerprinting command roughly every two minutes, cycling between the usernames `root` and `ubuntu`. The same command (`uname -s -v -n -r -m`) was also the first thing my very first outside visitor ran, so it appears to be a common bot routine.

### 2. Shared dropper campaign
Three sources, two of them in the same /24 network, ran an identical long shell command (a PATH export followed by a chain of `uname` fallbacks), created a small script with `printf`, made it executable with `chmod +x`, and fetched a file. All ten download events share one SHA-256 hash, and the sessions repeat every minute or two. The identical payload and command text across several addresses points to one tool or operator, though I cannot prove that from the logs.

### 3. Scripted SFTP uploads
Four uploads of a file named `sshd` happened, each exactly **five minutes after a root login**, from four different sources. Two uploads were empty files (the SHA-256 of zero bytes), and two had distinct non-empty contents. The identical five-minute delay suggests a shared script. A file named like the real SSH daemon is consistent with an attempt to replace or disguise a system binary.

### 4. Probing and honeypot checks
A few visitors ran unusual commands such as a RouterOS-style `/ip cloud print`, `ifconfig`, `echo Hi | cat -n`, and a `locate` with a random string. These look like checks for network devices or tests of whether the shell is real.

### 5. Default-credential spraying
18 different sources logged in with well-known default or cloud-image account names (`root`, `admin`, `ubuntu`, `azureuser`, `debian`, `ftpuser`). Many other usernames appeared only once or twice, which looks like bots working through long username lists.

## Credentials

| Rank | Username | Count |
|---|---|---|
| 1 | root | 19 |
| 2 | ubuntu | 6 |
| 3 | admin | 5 |
| 4 | akamai | 2 |
| 5 | ansible | 2 |

| Rank | Password | Count |
|---|---|---|
| 1 | 123456 | 11 |
| 2 | admin | 5 |
| 3 | ubuntu | 4 |
| 4 | 111111 | 3 |
| 5 | 123 | 3 |

## Commands run after login

| Command | Count | Likely purpose |
|---|---|---|
| `/bin/./uname -s -v -n -r -m` | 49 | Fingerprint the system |
| Script created with `printf` and made executable | 10 | Stage a script |
| `export PATH=... uname=$(uname ...)` chain | 10 | Fingerprint, then fetch a file |
| `uname -a` | 3 | Fingerprint the system |
| `/ip cloud print` | 2 | Probe for a router OS |
| `cat /proc/cpuinfo` | 2 | Check hardware |
| `ifconfig` | 2 | Check network configuration |

## File hashes (indicators)

Files are never opened or executed; they are identified by hash only.

| SHA-256 | Seen | Note |
|---|---|---|
| `af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32` | 10 | Shared across three sources |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 2 | Empty file |
| `595bae8df38a54d1ed9c253a6537d3901e96fd5c99e2324e7e74f1b456d41fca` | 1 | Uploaded as `sshd` |
| `abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023` | 1 | Uploaded as `sshd` |

Reputation lookups: *to be added after checking the hashes on a public service.*

## Detection rules

| Rule | Logic | MITRE ATT&CK | Alerts | Source IPs |
|---|---|---|---|---|
| HT-001 | Commands that fingerprint the system | T1082 System Information Discovery | 65 | 10 |
| HT-002 | Login using a well-known default account name | T1078.001 Valid Accounts: Default Accounts | 33 | 18 |
| HT-003 | File uploaded or downloaded during a session | T1105 Ingress Tool Transfer | 14 | 7 |

Alert counts are inflated by repeating bots, so the source-IP column is the better measure of how many separate visitors each rule caught.

## Planned additions

- Country and network-owner breakdown (GeoIP)
- Rule HT-004 for staging scripts with `chmod +x` (T1222.002)
- Rule HT-005 for network-configuration discovery (T1016)
- Charts: connections per day and per hour

## Conclusions

*Preliminary; to be finalised at the end of the collection period.*

- The internet scans a new SSH server within hours, and most traffic is automated.
- Most automated visitors fingerprint the machine first, then decide whether to deploy something.
- Several unrelated sources use the same payloads, so shared tooling is common.
- Detection rules are most useful when built from observed behaviour after login, because login attempts alone are not informative against a honeypot that accepts them.

## Limitations

- A single honeypot in one region gives a narrow view of internet-wide activity
- Many attackers are automated and do not reflect targeted threats
- Cowrie emulates a shell, so some attacker behaviour is cut short
- Because Cowrie accepts most logins, credential statistics describe attempts, not working passwords