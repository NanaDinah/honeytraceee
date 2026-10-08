# Setup Guide

How the HoneyTrace honeypot was deployed. Placeholders such as `<SERVER_IP>` and `<KEY_FILE>` stand in for real values, which are never committed to this repository.

> **Which machine am I on?** Server prompts look like `ubuntu@ip-...`; laptop prompts look like `user@hostname`. Commands in this guide are marked **[server]** or **[laptop]**.

## 1. Environment

| Item | Value |
|---|---|
| Cloud | AWS, single region |
| Instance | EC2 t3.micro, Ubuntu Server 24.04 LTS |
| Network | Default VPC in a new account with no other resources |
| Honeypot | Cowrie (pip package), run by an unprivileged user |
| Analysis | Java 21, Maven, Jackson, JUnit 5 |

## 2. Launch the instance

1. EC2, Launch instance, name `honeytrace-pot`
2. Image: Ubuntu Server 24.04 LTS; type: t3.micro
3. Create a key pair (ED25519, `.pem`). Store it in `~/.ssh/` with `chmod 400`. **Never place it inside the repository.**
4. Network: auto-assign public IP enabled; new security group with a single inbound rule, SSH (22) from **My IP**
5. No IAM role is attached and no AWS credentials are placed on the instance

**[laptop]** Connect:
```bash
ssh -i ~/.ssh/<KEY_FILE> ubuntu@<SERVER_IP>
```

## 3. Move real SSH off port 22

Port 22 will later belong to the honeypot, so the real SSH daemon moves to a different port.

1. In the security group, add an inbound rule: Custom TCP, the new admin port (22222), source **My IP**
2. **[server]** Create a config drop-in and restart SSH. On Ubuntu 24.04 SSH is socket-activated, so the socket unit is disabled so the port setting applies:
   ```bash
   sudo tee /etc/ssh/sshd_config.d/99-honeytrace.conf > /dev/null <<'EOF'
   Port 22222
   PermitRootLogin no
   PasswordAuthentication no
   EOF

   sudo sshd -t
   sudo systemctl disable --now ssh.socket
   sudo systemctl enable --now ssh.service
   sudo systemctl restart ssh
   sudo ss -tlnp | grep sshd
   ```
3. **[laptop]** Test from a **second** terminal before closing the first:
   ```bash
   ssh -p 22222 -i ~/.ssh/<KEY_FILE> ubuntu@<SERVER_IP>
   ```
4. Reboot once (`sudo reboot`) and confirm the new port still works

Tip: add a `Host` entry with `ServerAliveInterval 30` to `~/.ssh/config` so sessions don't drop when idle. Keep that file out of the repository.

## 4. Install Cowrie

**[server]** Dependencies and an unprivileged user:
```bash
sudo apt update
sudo apt -y install git python3-venv libssl-dev libffi-dev build-essential libpython3-dev authbind iptables
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie
```

**[server, as `cowrie`]** Install and start (Cowrie is now distributed as a pip package):
```bash
mkdir my-honeypot && cd my-honeypot
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install cowrie
cowrie init
cowrie start
cowrie status
```

Cowrie listens on port 2222 by default and writes JSON events to `var/log/cowrie/cowrie.json` inside `my-honeypot`.

**Local test** **[server, as `ubuntu`]**:
```bash
ssh -p 2222 root@localhost
```
Any password gives a fake Debian shell. Run a few commands and `exit`, then check the log:
```bash
sudo tail -n 5 /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
```

## 5. Redirect port 22 to Cowrie

**[server]**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo apt -y install iptables-persistent
sudo netfilter-persistent save
sudo iptables -t nat -L PREROUTING -n
```

Verify only Cowrie (2222) and the real SSH (22222) are listening:
```bash
sudo ss -tlnp | grep -E ':22\b|:22222|:2222'
```

## 6. Restart Cowrie after reboots

**[server]**
```bash
(sudo -u cowrie crontab -l 2>/dev/null; echo '@reboot cd /home/cowrie/my-honeypot && /home/cowrie/my-honeypot/cowrie-env/bin/cowrie start') | sudo -u cowrie crontab -
sudo -u cowrie crontab -l
```

## 7. Restrict outbound traffic

Cowrie's fake `wget`/`curl` can fetch URLs to capture malware, so outbound traffic is limited.

In the security group, replace the default "All traffic" outbound rule with:

| Type | Port | Destination |
|---|---|---|
| HTTPS | 443 | 0.0.0.0/0 |
| HTTP | 80 | 0.0.0.0/0 |
| Custom UDP (DNS) | 53 | 0.0.0.0/0 |

Verify with `sudo apt update` on the server. Downloaded files are never executed.

## 8. Go live

Only after the steps above are complete:

1. Inbound rule for port 22: change the source from **My IP** to **Anywhere-IPv4**
2. Leave the admin port restricted to **My IP**
3. **[laptop]** Test the redirect from outside:
   ```bash
   ssh -o UserKnownHostsFile=/dev/null root@<SERVER_IP>
   ```
   Any password should give the fake shell
4. **[server]** Watch events arrive:
   ```bash
   sudo tail -f /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
   ```

## 9. Collect logs

**[laptop]** Pull the logs over the admin port (raw logs are git-ignored under `data/raw/`):
```bash
mkdir -p data/raw
rsync -avz -e "ssh -p 22222 -i ~/.ssh/<KEY_FILE>" --rsync-path="sudo rsync" \
  ubuntu@<SERVER_IP>:/home/cowrie/my-honeypot/var/log/cowrie/ data/raw/
```

## 10. Run the analysis

**[laptop]**
```bash
mvn test
mvn -q org.codehaus.mojo:exec-maven-plugin:3.1.0:java \
  -Dexec.mainClass=com.honeytrace.Main \
  -Dexec.args="data/raw/cowrie.json <MY_OWN_IP>"
```
Pass your own IP as an extra argument so test sessions are excluded.

## 11. Troubleshooting notes

| Problem | Cause and fix |
|---|---|
| `Identity file ... not accessible` on the server | The key lives on the laptop only; you ran `ssh` from inside the server |
| `cp: cannot stat 'etc/cowrie.cfg.dist'` | Old install steps; current Cowrie installs with pip and uses `cowrie init` |
| `cowrie.json: No such file` | Command was run on the wrong machine; check `hostname` first |
| SSH timeout after changing the port | Security group is missing the new admin port rule, or my IP changed |
| `Broken pipe` | Idle SSH session dropped; the honeypot keeps running regardless |

## 12. Lessons learned

- Always confirm which machine a terminal is on (`hostname`) before running anything
- Test a new SSH port from a second session before closing the working one
- Install steps in older guides go stale; check the project's current documentation
- Keep keys, raw logs and runtime folders out of version control, and review `git ls-files` before pushing