[**<u>Project 1 - Network Intrusion Detection System (NIDS)
Rule</u>**](https://tinyurl.com/t3v5x8t3) [**<u>Creation and Testing
Lab</u>**](https://tinyurl.com/t3v5x8t3)

**Problem** **Statement:** Develop and test a robust set of custom rules
for a Network Intrusion Detection System (NIDS) to identify and flag
common cyber-attacks in real-time, reducing the mean time to detect
threats within a network.

**Use** **Case:** Create a virtualized security lab where an open-source
NIDS like Snort or Suricata is deployed to monitor network traffic. The
system will be configured with custom rules designed to detect specific
malicious activities, such as reconnaissance scans, brute-force login
attempts, and known malware communication, providing immediate alerts to
security analysts for investigation.

**Project** **2** **-** **Web** **Application** **Firewall** **(WAF)**
**Rule** **Development** **and** **Evasion** **Testing** **Lab**

**Problem** **Statement:** Design, implement, and test a set of Web
Application Firewall (WAF) rules to protect a web application from
common vulnerabilities like SQL Injection (SQLi) and Cross-Site
Scripting (XSS), and then attempt to bypass these rules to improve their
resilience.

**Use** **Case:** Deploy the ModSecurity WAF on a web server hosting a
vulnerable application (e.g., DVWA). Security administrators will write
and refine custom rules to block malicious web requests. The project
involves a red-teaming phase, where evasion techniques are used to
challenge the rules, resulting in a hardened security posture that
minimizes the risk of web-based attacks.

**Project** **3** **-** **Threat** **Intelligence** **Feed**
**Processor** **and** **Anomaly** **Detector**

**Problem** **Statement:** Develop a system that automates the
consumption of open-source threat intelligence (TI) feeds to detect
potential security threats within system and network logs, enabling
faster identification of malicious indicators of compromise (IOCs).

**Use** **Case:** Build a Python-based tool that runs on a schedule,
fetches the latest threat data (malicious IPs, domains, file hashes)
from public feeds like AbuseIPDB and AlienVault OTX,

and stores it locally. The tool will then compare these IOCs against
simulated network or system logs to find matches, generating alerts for
any suspicious activity, such as communication with a known
command-and-control server.
