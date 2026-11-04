# Task 4: Network Intrusion Detection System

**CodeAlpha Cybersecurity Internship**

## 1. Overview

This task builds a network-based intrusion detection system (NIDS) with **Suricata** in a Kali Linux virtual machine. The project writes custom detection rules, watches network traffic continuously, raises alerts when it sees suspicious activity, responds automatically by blocking the attacker, and shows the detected attacks on a dashboard.

All attacks were simulated inside a private lab on the same virtual machine. No real network or other person's system was scanned or attacked.

## 2. Task Requirements and How They Were Met

| Requirement | What was done | Evidence |
|---|---|---|
| Set up a network-based IDS with Snort or Suricata | Installed and configured Suricata 8.0.7 | Screenshots 03, 05 |
| Configure rules and alerts | Loaded the Emerging Threats Open rule set and wrote 3 custom rules (ping, port scan, SSH attempt) | 04, 07, 08 |
| Monitor network traffic continuously | Ran Suricata on a live network interface and watched alerts appear in real time | 09, 11 |
| Implement response mechanisms | A Python responder reads Suricata alerts and blocks the attacker's address with the firewall | 14 to 19 |
| Optionally, visualize the attacks | A generated HTML dashboard with charts of the alerts | 20 |

## 3. Lab Architecture

An IDS can only see traffic that passes through the interface it watches, and traffic that a computer sends to itself never leaves it. To get realistic traffic inside one virtual machine, the lab uses a Linux network namespace (a separate pretend computer called `attacker`) joined to Kali by a virtual cable.

```mermaid
flowchart LR
    A["Attacker namespace<br/>192.168.100.2<br/>(ping, nmap)"] -- "virtual cable<br/>veth-att to veth-ids" --> K["Kali VM<br/>192.168.100.1<br/>veth-ids"]
    K --> S["Suricata<br/>custom rules"]
    S --> F["fast.log and eve.json<br/>alert logs"]
    F --> R["ids_responder.py<br/>blocks attacker with iptables"]
    F --> D["make_dashboard.py<br/>dashboard.html"]
```

| Part | Address | Role |
|---|---|---|
| Kali VM, `veth-ids` | 192.168.100.1 | Protected machine, watched by Suricata |
| `attacker` namespace, `veth-att` | 192.168.100.2 | Simulated attacker |
| Kali main interface `eth1` | 10.0.0.2 (gateway 10.0.0.1) | Real network connection, found with `ip route` |

## 4. Tools and Versions

| Tool | Version |
|---|---|
| Kali Linux (VM) | 2026.2 |
| Suricata | 8.0.7 RELEASE |
| Nmap | 7.99 |
| Rule set | Emerging Threats Open (via `suricata-update`) |
| Response | Python 3 and iptables |

## 5. Implementation

### 5.1 Find the network interfaces

`ip -br a` lists the interfaces, and `ip route` shows which one carries traffic to the internet. The default route goes through `eth1`.

![Network interfaces](screenshots/01-network-interfaces.png)

![Default route](screenshots/02-ip-route.png)

### 5.2 Install Suricata

```bash
sudo apt update
sudo apt install -y suricata jq
suricata -V
```

![Suricata version](screenshots/03-suricata-version.png)

### 5.3 Download the rule set and test the configuration

```bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

`suricata-update` loaded 69,325 rules, of which 53,356 are enabled. The configuration test processed 53,361 signatures and ended with "Configuration provided was successfully loaded."

![Rules downloaded](screenshots/04-rules-downloaded.png)

![Configuration test](screenshots/05-config-test.png)

### 5.4 Build the attacker lab

```bash
sudo ip netns add attacker
sudo ip link add veth-att type veth peer name veth-ids
sudo ip link set veth-att netns attacker
sudo ip addr add 192.168.100.1/24 dev veth-ids
sudo ip link set veth-ids up
sudo ip netns exec attacker ip addr add 192.168.100.2/24 dev veth-att
sudo ip netns exec attacker ip link set veth-att up
sudo ip netns exec attacker ip link set lo up
sudo ip netns exec attacker ping -c 2 192.168.100.1
```

The ping between the two ends shows 2 packets sent, 2 received and 0% loss, so the virtual cable works.

![Attacker lab](screenshots/06-attacker-lab.png)

### 5.5 Write custom rules

The rules are in [`rules/local.rules`](rules/local.rules).

| SID | Detects | How |
|---|---|---|
| 1000001 | Ping (ICMP echo request) | Matches ICMP type 8 sent to the protected network |
| 1000002 | TCP SYN port scan | Alerts when one source sends 15 or more SYN packets within 5 seconds (`detection_filter`) |
| 1000003 | SSH connection attempt | Matches a SYN packet to TCP port 22 |

![Custom rules](screenshots/07-custom-rules.png)

The rule file was tested before use. Three rules loaded with no failures.

```bash
sudo suricata -T -S rules/local.rules -c /etc/suricata/suricata.yaml -v
```

Suricata printed one warning: rule 1000003 does not state a direction, so Suricata disabled it for the return direction. This is harmless, because the rule is meant to match only traffic going to port 22. Adding `flow:to_server` to the rule would remove the warning.

![Rule test](screenshots/08-rules-test.png)

### 5.6 Start continuous monitoring

```bash
sudo suricata -c /etc/suricata/suricata.yaml -S rules/local.rules -i veth-ids -k none -l logs
```

The options mean: `-S` use only the custom rules, `-i veth-ids` watch the virtual cable, `-k none` skip checksum checks (virtual interfaces often have unreliable checksums), `-l logs` write logs to the `logs` folder. "Engine started" confirms it is running. Suricata keeps running and writes every alert to `logs/fast.log` and `logs/eve.json`.

![Suricata running](screenshots/09-suricata-running.png)

### 5.7 Simulate attacks and watch the alerts

From the attacker namespace:

```bash
sudo ip netns exec attacker ping -c 3 192.168.100.1
sudo ip netns exec attacker nmap -sS -p 1-100 192.168.100.1
sudo ip netns exec attacker nmap -sS -p 22 192.168.100.1
```

![Attack commands](screenshots/10-attack-commands.png)

Alerts appeared live in `fast.log`, showing the rule message, priority and the path `192.168.100.2 -> 192.168.100.1`.

![Live alerts](screenshots/11-live-alerts.png)

Counting the alerts by rule shows that all three rules fired:

```bash
sudo grep -o "LOCAL [^[]*" logs/fast.log | sed 's/ *$//' | sort | uniq -c
```

| Alerts | Rule |
|---|---|
| 3 | LOCAL ICMP echo request (ping) detected |
| 85 | LOCAL Possible TCP SYN port scan |
| 2 | LOCAL SSH connection attempt |

![Alert summary](screenshots/12-alert-summary.png)

The port-scan rule alerts on every SYN packet after the threshold of 15 is crossed, which is why one scan produces many alerts.

### 5.8 Response mechanism

[`scripts/ids_responder.py`](scripts/ids_responder.py) reads Suricata's `eve.json` live. When the port-scan rule (SID 1000002) fires, it blocks the attacker's address with `iptables`.

Safety features built into the script:

- **Dry run by default.** It only reports what it would block until `--block` is used.
- **Protected addresses** (the lab and gateway addresses) are never blocked.
- **Input validation.** An address is checked with Python's `ipaddress` module before it reaches the firewall command.
- **No shell.** The firewall command is run with an argument list, which prevents command injection (a lesson from Task 3).
- **Audit log.** Every alert and action is written to `logs/response.log`.
- **Undo.** `--unblock ADDRESS` removes the block.

![Response script created](screenshots/13-response-script-created.png)

**Dry run first.** The responder watched the live alerts and reported what it would do.

```bash
sudo python3 scripts/ids_responder.py
```

![Responder live alerts](screenshots/14-responder-live-alerts.png)

The log shows the start line, the `would block 192.168.100.2 (dry run)` decision and the count of alert lines.

![Dry run proof](screenshots/15-responder-dry-run-proof.png)

**Real blocking.**

```bash
sudo python3 scripts/ids_responder.py --block
```

At 06:08:01 the port-scan alert fired and in the same second the responder logged `RESPONSE blocked 192.168.100.2 (exit code 0)`.

![Attacker blocked](screenshots/16-attacker-blocked.png)

**Verification.** Before the attack, pings from the attacker worked. After the block, they failed with 100% packet loss, and the firewall table shows a DROP rule for the attacker's address.

![Ping fails after block](screenshots/17-ping-fails-after-block.png)

![Firewall rule](screenshots/18-iptables-block-rule.png)

**Recovery.** The block was removed and pings worked again with 0% loss.

```bash
sudo python3 scripts/ids_responder.py --unblock 192.168.100.2
```

![Unblocked](screenshots/19-unblocked.png)

### 5.9 Dashboard (optional)

[`scripts/make_dashboard.py`](scripts/make_dashboard.py) reads `eve.json` and `response.log` and writes a self-contained web page at [`dashboard/dashboard.html`](dashboard/dashboard.html).

```bash
sudo python3 scripts/make_dashboard.py
```

For the whole test session the dashboard shows 269 alerts from one source address (192.168.100.2), made up of 255 port-scan alerts, 10 ping alerts and 4 SSH alerts, with 1 address blocked. It also charts alerts per minute and by severity, and lists the response actions.

![Dashboard](screenshots/20-dashboard.png)

## 6. Observations

- Detection worked for all three attack types, using rules written for this lab.
- The response was fast: the block was applied in the same second as the first port-scan alert.
- Alerts continued after the block (the dashboard shows 3 alerts at 06:09, consistent with the three pings sent after blocking). This is expected, because Suricata captures packets before the firewall drops them.
- The scan itself still completed, because detection happens first and the block follows. This system is an **IDS with an automatic response**, not an inline **IPS** that stops packets before they arrive.

## 7. Limitations

- The response is reactive, as explained above. An inline IPS mode (for example NFQUEUE) would block packets before they reach the target.
- Blocking is by source address only. An attacker with spoofed or changing addresses could avoid it, and a wrong rule could block a real user. For this reason the script defaults to dry run.
- Firewall blocks made by the script are not saved and disappear after a reboot.
- The port-scan rule produces one alert per packet after the threshold, which is noisy. Alert grouping would make the output easier to read.
- The test watched a virtual lab interface. To watch the real connection, start Suricata with `-i eth1`.
- Only IPv4 lab traffic was tested. The `eve.json` file is not included in this repository to keep it small. `fast.log` and `response.log` are included in the `logs` folder.

## 8. Ethical and Responsible Use

All scanning and blocking was done on a private virtual lab, against the author's own virtual machine. Scanning or attacking networks without written permission is illegal in most countries.

## 9. Conclusion

This task delivers a working network intrusion detection system. Suricata monitored a live interface with custom rules and detected pings, port scans and SSH attempts. A Python responder blocked the attacker automatically and the block was verified and removed. The dashboard summarises the detected attacks. The design choices (dry run by default, protected addresses, input validation and no shell) apply the secure coding lessons from Task 3 to a security tool.

## 10. Repository Structure

```
Task-4-Network-IDS/
├── README.md
├── rules/
│   └── local.rules
├── scripts/
│   ├── ids_responder.py
│   └── make_dashboard.py
├── dashboard/
│   └── dashboard.html
├── logs/
│   ├── fast.log
│   └── response.log
└── screenshots/
    └── 01 to 20 (PNG files)
```
