Absolutely ✅ — here’s the **ready-to-drop content** for your
📘 `suricata_basics.md` file (just copy and paste it into your repo).

---

````markdown
# ⚙️ Suricata Basics

## 🧩 Overview

**Suricata** is an open-source, high-performance **Intrusion Detection System (IDS)**, **Intrusion Prevention System (IPS)**, and **Network Security Monitoring (NSM)** tool developed by the **Open Information Security Foundation (OISF)**.  

It monitors network traffic in real-time, detects malicious patterns using **signature-based rules**, and generates detailed alerts and logs for analysis.

---

## 🧠 Key Features

- Real-time network traffic inspection (IDS/IPS/NSM)
- Protocol analysis (HTTP, TLS, DNS, SMB, etc.)
- Multi-threading for high-performance packet processing
- JSON-formatted event logging (`eve.json`)
- Compatible with **Emerging Threats** and **custom rules**
- Integration support for **Wazuh**, **Splunk**, and **ELK Stack**

---

## 🧩 Installation (Ubuntu/Kali)

Update and install Suricata:
```bash
sudo apt update
sudo apt install -y suricata
````

Check the version:

```bash
suricata -V
```

Enable and start the service:

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
```

Verify the status:

```bash
sudo systemctl status suricata
```

---

## 📁 Important Directories

| Path                          | Description                  |
| ----------------------------- | ---------------------------- |
| `/etc/suricata/`              | Main configuration directory |
| `/etc/suricata/suricata.yaml` | Core configuration file      |
| `/etc/suricata/rules/`        | Contains all rule files      |
| `/var/log/suricata/eve.json`  | JSON-formatted event log     |
| `/var/log/suricata/fast.log`  | Simplified alert log         |

---

## ⚙️ Basic Configuration

Edit Suricata’s main configuration:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Ensure these output options are enabled:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
```

Restart Suricata:

```bash
sudo systemctl restart suricata
```

---

## 🧾 Writing Custom Rules

Suricata uses **Snort-compatible syntax** for its rules.

Edit your local rule file:

```bash
sudo nano /etc/suricata/rules/local.rules
```

Add this example **SQL Injection detection rule**:

```bash
alert http any any -> any any (msg:"Possible SQL Injection attempt"; flow:to_server,established; content:"select"; nocase; http_uri; classtype:web-application-attack; sid:1000001; rev:1;)
alert http any any -> any any (msg:"SQL Injection OR '1'='1'"; content:"' OR '1'='1"; nocase; http_uri; classtype:web-application-attack; sid:1000002; rev:1;)
```

Each part of the rule:

| Component                 | Description                      |
| ------------------------- | -------------------------------- |
| `alert`                   | Action (log/alert)               |
| `http any any -> any any` | Protocol and direction           |
| `msg`                     | Message displayed when triggered |
| `content`                 | What to look for in the payload  |
| `sid`                     | Unique rule ID                   |
| `rev`                     | Revision number                  |

---

## 🔁 Load & Test Rules

Reload Suricata to apply rules:

```bash
sudo suricata-update
sudo systemctl restart suricata
```

Test configuration validity:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

## 🧪 Triggering Alerts

Use **curl** to simulate attacks and test detection:

Example 1 – SQL Injection on a vulnerable site:

```bash
curl "http://testphp.vulnweb.com/listproducts.php?cat=1' OR '1'='1"
```

Example 2 – Local vulnerable web app:

```bash
curl "http://192.168.50.130:5000/login?user=admin%27--&pass=admin"
```

---

## 🔍 Viewing Alerts & Logs

Tail the live event log:

```bash
tail -f /var/log/suricata/eve.json
```

Filter specific events:

```bash
grep "SQL Injection" /var/log/suricata/eve.json
```

Simplified alert output:

```bash
sudo cat /var/log/suricata/fast.log
```

---

## 🧰 Common Commands

| Command                                   | Description                 |
| ----------------------------------------- | --------------------------- |
| `sudo systemctl start suricata`           | Start Suricata              |
| `sudo systemctl stop suricata`            | Stop Suricata               |
| `sudo systemctl restart suricata`         | Restart the service         |
| `sudo suricata-update`                    | Update rules and signatures |
| `sudo suricata -T`                        | Test config and rules       |
| `sudo tail -f /var/log/suricata/eve.json` | View live alerts            |

---

## ⚠️ Troubleshooting

| Problem                          | Solution                                                                   |
| -------------------------------- | -------------------------------------------------------------------------- |
| No alerts generated              | Ensure `local.rules` is included in `suricata.yaml` and Suricata restarted |
| `eve.json` not updating          | Check permissions or verify `outputs` in YAML                              |
| “Failed to bind interface” error | Stop other network tools using same interface                              |
| SQL Injection test not logged    | Confirm Suricata monitors the correct network interface                    |

---

## 📊 Integration Options

Suricata integrates easily with:

* **Wazuh** — SIEM + alert correlation
* **Splunk / ELK Stack** — data visualization and analytics
* **CrowdSec** — community threat detection
* **Zeek (Bro)** — advanced network analysis

---

## 🧾 References

* [Suricata Official Docs](https://docs.suricata.io/)
* [OISF Website](https://oisf.net/)
* [Emerging Threats Rules](https://rules.emergingthreats.net/)
* [Wazuh + Suricata Integration Guide](https://documentation.wazuh.com/current/proof-of-concept-guide/suricata.html)

---

> 🛠️ Maintained by **Ruffzi069**
> 📘 Purpose: Educational — Demonstrating Suricata basics for security monitoring and log analysis.



Would you like me to create the **next GitBook page** called
`suricata_wazuh_integration.md` — showing how to link Suricata logs into Wazuh’s dashboard?
