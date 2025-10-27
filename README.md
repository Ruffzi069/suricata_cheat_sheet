# 🛡️ Suricata Log Monitoring — Mini Guide

Welcome to the **Suricata Cheat Sheet and Guide**!  
This documentation helps you quickly set up and understand **Suricata**, the powerful open-source network intrusion detection and prevention system (IDS/IPS).

---

## 🎯 What This Guide Covers

This GitBook provides:
- A **simple explanation** of Suricata’s purpose and architecture  
- **Installation steps** on Ubuntu / Kali  
- **Basic configuration** and verification  
- **Custom rule creation** (e.g., SQL Injection detection)  
- **Log monitoring tips** using `eve.json` and tools like Wazuh  

---

## 🧠 What is Suricata?

**Suricata** is a high-performance **IDS/IPS** and **network security monitoring** (NSM) engine.  
It analyzes packets in real-time, detects threats using signatures and anomalies, and logs detailed alerts.

Suricata can:
- Detect **intrusions and attacks** using rule-based signatures  
- Perform **file extraction** and **protocol analysis** (HTTP, TLS, DNS, SMB, etc.)  
- Generate detailed **JSON logs** in `eve.json`  
- Integrate with **Wazuh, Splunk, or ELK** for analytics

---

## ⚙️ Quick Setup

```bash
sudo apt update
sudo apt install -y suricata

