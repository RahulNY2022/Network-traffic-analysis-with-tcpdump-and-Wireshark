# Network Analysis Lab: Detection and Response

## Lab Overview
This hands-on lab provides deep-dive exercises in network traffic analysis using industry-standard tools. You'll learn to capture, analyze, and interpret network data crucial for security detection and incident response.

**Duration:** 4-6 hours  
**Difficulty:** Intermediate to Advanced  
**Prerequisites:** Basic networking knowledge (TCP/IP, protocols), Linux command line familiarity

---

## Lab Objectives

By completing this lab, you will:
- Master packet capture and analysis with tcpdump
- Perform deep protocol analysis using Wireshark
- Analyze AWS VPC Flow Logs for cloud security monitoring
- Identify malicious network patterns and anomalies
- Build detection rules based on network indicators

---

## Lab Environment Setup

### Required Tools
- Linux system (Ubuntu 20.04+ recommended) or macOS
- tcpdump (pre-installed on most systems)
- Wireshark (download from wireshark.org)
- AWS CLI (for VPC Flow Logs section)
- Sample PCAP files (provided in exercises)

### Verification
```bash
# Check tcpdump installation
sudo tcpdump --version

# Check Wireshark installation
wireshark --version

# Check AWS CLI (if doing AWS section)
aws --version
```

---

## Part 1: tcpdump Fundamentals

### Exercise 1.1: Basic Packet Capture

**Objective:** Learn to capture network traffic using tcpdump

```bash
# List available network interfaces
sudo tcpdump -D

# Capture packets on specific interface (replace eth0 with your interface)
sudo tcpdump -i eth0

# Capture with packet count limit
sudo tcpdump -i eth0 -c 10

# Capture and save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read from saved file
sudo tcpdump -r capture.pcap
```

**Key Concepts:**
- `-i`: Interface selection
- `-c`: Count (number of packets)
- `-w`: Write to file
- `-r`: Read from file

### Exercise 1.2: Display Options and Verbosity

```bash
# Verbose output with more packet details
sudo tcpdump -i eth0 -v

# Very verbose (even more details)
sudo tcpdump -i eth0 -vv

# Extremely verbose (maximum detail)
sudo tcpdump -i eth0 -vvv

# Show absolute sequence numbers
sudo tcpdump -i eth0 -S

# Don't convert addresses to names (faster, shows IPs)
sudo tcpdump -i eth0 -n

# Don't convert port numbers to service names
sudo tcpdump -i eth0 -nn

# Print packet data in hex and ASCII
sudo tcpdump -i eth0 -X

# Show link-level headers (Ethernet)
sudo tcpdump -i eth0 -e
```

### Exercise 1.3: Basic Filtering

**Capture specific protocols:**

```bash
# TCP traffic only
sudo tcpdump -i eth0 tcp

# UDP traffic only
sudo tcpdump -i eth0 udp

# ICMP traffic (ping)
sudo tcpdump -i eth0 icmp

# ARP traffic
sudo tcpdump -i eth0 arp
```

**Capture by host:**

```bash
# Traffic to/from specific host
sudo tcpdump -i eth0 host 192.168.1.100

# Traffic from specific host
sudo tcpdump -i eth0 src host 192.168.1.100

# Traffic to specific host
sudo tcpdump -i eth0 dst host 192.168.1.100
```

**Capture by port:**

```bash
# HTTP traffic (port 80)
sudo tcpdump -i eth0 port 80

# HTTPS traffic (port 443)
sudo tcpdump -i eth0 port 443

# SSH traffic (port 22)
sudo tcpdump -i eth0 port 22

# Source port filtering
sudo tcpdump -i eth0 src port 53

# Destination port filtering
sudo tcpdump -i eth0 dst port 443
```

### Exercise 1.4: Advanced Filtering with Boolean Logic

```bash
# Combine filters with AND
sudo tcpdump -i eth0 'tcp and port 80'

# Combine with OR
sudo tcpdump -i eth0 'tcp or udp'

# Use NOT to exclude
sudo tcpdump -i eth0 'not port 22'

# Complex filter: HTTP/HTTPS traffic to specific host
sudo tcpdump -i eth0 'host 192.168.1.100 and (port 80 or port 443)'

# Traffic between two hosts
sudo tcpdump -i eth0 'host 192.168.1.100 and host 192.168.1.200'

# Exclude local network traffic
sudo tcpdump -i eth0 'not src net 192.168.1.0/24'
```

### Exercise 1.5: Detecting Suspicious Activity

**Scan detection (SYN scans):**

```bash
# Capture SYN packets without ACK (potential port scan)
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0'

# NULL scan detection (all flags off)
sudo tcpdump -i eth0 'tcp[tcpflags] = 0'

# XMAS scan detection (FIN, PSH, URG flags set)
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-fin|tcp-push|tcp-urg) != 0'
```

**DNS queries:**

```bash
# All DNS queries
sudo tcpdump -i eth0 'udp port 53'

# DNS queries to specific domain (requires payload inspection)
sudo tcpdump -i eth0 -vvv 'udp port 53' | grep -i "malicious-domain.com"
```

**Large packets (potential data exfiltration):**

```bash
# Packets larger than 1000 bytes
sudo tcpdump -i eth0 'greater 1000'

# Outbound traffic with large packets
sudo tcpdump -i eth0 'dst net not 192.168.1.0/24 and greater 1000'
```

### Exercise 1.6: Real-World Detection Scenarios

**Scenario 1: Detect SQL Injection Attempts**

```bash
# Capture HTTP traffic and save for analysis
sudo tcpdump -i eth0 -A 'tcp port 80' -w http_traffic.pcap

# Read and search for SQL keywords
sudo tcpdump -A -r http_traffic.pcap | grep -i "select\|union\|insert\|update\|delete"
```

**Scenario 2: Identify C2 Beaconing**

```bash
# Monitor periodic connections to external IPs (save for time analysis)
sudo tcpdump -i eth0 -nn 'dst net not 192.168.0.0/16 and dst net not 10.0.0.0/8' -w beacon_check.pcap

# To analyze timing later, use:
tcpdump -r beacon_check.pcap -tt | awk '{print $1}' | head -20
```

**Scenario 3: Monitor for Credential Theft**

```bash
# Capture authentication traffic (risky protocols)
sudo tcpdump -i eth0 -A '(port 21 or port 23 or port 110 or port 143)' -w cleartext_auth.pcap
```

### Exercise 1.7: Packet Count Statistics

```bash
# Count packets by protocol
sudo tcpdump -i eth0 -c 1000 -nn | awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -rn

# Monitor traffic to/from specific subnet
sudo tcpdump -i eth0 -c 100 net 192.168.1.0/24 -w subnet_traffic.pcap
```

---

## Part 2: Wireshark Deep Analysis

### Exercise 2.1: Wireshark Interface Basics

**GUI Navigation:**
1. Launch Wireshark: `sudo wireshark` or `wireshark capture.pcap`
2. Main window components:
   - Packet List Pane (top)
   - Packet Details Pane (middle)
   - Packet Bytes Pane (bottom)
   - Filter toolbar (top)

**Quick Start:**
- Start capture: Click shark fin icon
- Stop capture: Click red square
- Open existing capture: File → Open

### Exercise 2.2: Display Filters

Wireshark uses Berkeley Packet Filter (BPF) syntax for capture filters and its own display filter syntax.

**Basic Display Filters:**

```
# IP address filtering
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 192.168.1.100

# Protocol filtering
http
dns
tcp
udp
ssl
ssh

# Port filtering
tcp.port == 80
tcp.dstport == 443
udp.srcport == 53

# Combine with Boolean operators
http and ip.addr == 192.168.1.100
tcp.port == 80 or tcp.port == 443
not arp
```

**Advanced Display Filters:**

```
# HTTP methods
http.request.method == "GET"
http.request.method == "POST"

# HTTP response codes
http.response.code == 200
http.response.code >= 400

# DNS queries
dns.qry.name contains "malware"
dns.flags.response == 0

# TCP flags
tcp.flags.syn == 1 and tcp.flags.ack == 0
tcp.flags.reset == 1

# Packet size
frame.len > 1000
tcp.len > 500

# Follow TCP stream
tcp.stream eq 0
```

### Exercise 2.3: Statistical Analysis

**Protocol Hierarchy:**
1. Statistics → Protocol Hierarchy
2. Review distribution of protocols
3. Identify unusual protocol usage

**Conversations:**
1. Statistics → Conversations
2. Select TCP, UDP, or IP tabs
3. Sort by packets or bytes
4. Look for:
   - High volume connections
   - Unusual port usage
   - Foreign IP addresses

**Endpoints:**
1. Statistics → Endpoints
2. Identify top talkers
3. Flag suspicious IPs

**IO Graphs:**
1. Statistics → I/O Graph
2. Visualize traffic patterns over time
3. Look for:
   - Traffic spikes
   - Periodic beaconing
   - Data exfiltration patterns

### Exercise 2.4: Following Streams

**TCP Stream Analysis:**
1. Right-click any TCP packet
2. Follow → TCP Stream
3. View complete conversation
4. Look for:
   - Credentials in clear text
   - Commands executed
   - File transfers
   - Application data

**Filter Options in Stream:**
- Show data as ASCII, EBCDIC, Hex Dump, C Arrays, Raw
- Filter by direction
- Save stream to file

### Exercise 2.5: HTTP Analysis

**HTTP Request/Response Analysis:**

```
# Filter HTTP requests
http.request

# Filter specific URI
http.request.uri contains "admin"

# Filter by User-Agent (potential malware)
http.user_agent contains "python"

# Export HTTP objects
File → Export Objects → HTTP
```

**Indicators of Compromise (IOCs) to Look For:**
- Suspicious User-Agents
- Encoded or obfuscated parameters
- Non-standard HTTP methods
- Unusual Content-Types
- Large POST requests (data exfiltration)

### Exercise 2.6: DNS Analysis

**DNS Query Analysis:**

```
# Show all DNS queries
dns.flags.response == 0

# Show all DNS responses
dns.flags.response == 1

# Find specific domain lookups
dns.qry.name contains "suspicious"

# Look for DNS tunneling (unusual query length)
dns.qry.name.len > 50

# Check for fast-flux (multiple IPs for one domain)
dns.resp.name == "malware.com"
```

**DNS Anomalies:**
- Excessive subdomain queries
- Queries to suspicious TLDs
- High volume of NXDOMAIN responses
- DNS over non-standard ports

### Exercise 2.7: SSL/TLS Analysis

**Certificate Inspection:**
1. Filter: `ssl.handshake.type == 11`
2. Expand Secure Sockets Layer → TLSv1.2 → Handshake Protocol: Certificate
3. Check:
   - Certificate validity
   - Issuer information
   - Subject Alternative Names
   - Self-signed certificates (potential MITM)

**TLS Analysis:**

```
# Client Hello
ssl.handshake.type == 1

# Server Hello
ssl.handshake.type == 2

# Certificate
ssl.handshake.type == 11

# Look for weak ciphers
ssl.handshake.ciphersuite in {0x0004 0x0005}
```

### Exercise 2.8: Malware Traffic Analysis

**Hands-On Exercise: Analyze Suspicious Traffic**

Download sample PCAP files from:
- malware-traffic-analysis.net
- contagiodump.blogspot.com

**Analysis Checklist:**

1. **Initial Triage:**
   - Statistics → Protocol Hierarchy
   - Statistics → Conversations
   - Look for beaconing patterns in I/O Graphs

2. **HTTP Analysis:**
   ```
   http.request
   ```
   - Check User-Agents
   - Review URIs for suspicious patterns
   - Export HTTP objects

3. **DNS Analysis:**
   ```
   dns
   ```
   - Identify contacted domains
   - Check for DGA (Domain Generation Algorithm) patterns
   - Look for excessive DNS queries

4. **C2 Communication:**
   - Regular beacon intervals
   - Small request, small response patterns
   - Unusual ports or protocols

5. **Extract IOCs:**
   - IP addresses
   - Domain names
   - URLs
   - File hashes (from exported objects)

### Exercise 2.9: Wireshark for Incident Response

**Scenario: Ransomware Infection**

**Step 1: Timeline Reconstruction**
```
# Sort by time
Click "Time" column
```

**Step 2: Identify Patient Zero**
```
# Find SMB traffic (WannaCry, NotPetya)
smb2

# Find RDP brute force
tcp.port == 3389 and tcp.flags.syn == 1
```

**Step 3: Lateral Movement**
```
# Look for authentication attempts
ntlmssp
kerberos
```

**Step 4: Data Staging/Exfiltration**
```
# Large outbound transfers
ip.dst_host != 192.168.0.0/16 and tcp.len > 1000
```

**Step 5: Document Findings**
- File → Export Packet Dissections → As CSV
- Create timeline with key events
- Extract IOCs for threat intelligence

---

## Part 3: AWS VPC Flow Logs Analysis

### Exercise 3.1: Understanding VPC Flow Logs

**Flow Log Format:**
```
<version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
```

**Example Flow Log Entry:**
```
2 123456789012 eni-abc123de 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK
```

**Field Breakdown:**
- `version`: 2
- `account-id`: 123456789012
- `interface-id`: eni-abc123de
- `srcaddr`: 172.31.16.139 (source IP)
- `dstaddr`: 172.31.16.21 (destination IP)
- `srcport`: 20641 (source port)
- `dstport`: 22 (destination port - SSH)
- `protocol`: 6 (TCP)
- `packets`: 20 packets
- `bytes`: 4249 bytes
- `start`: 1418530010 (Unix timestamp)
- `end`: 1418530070 (Unix timestamp)
- `action`: ACCEPT or REJECT
- `log-status`: OK

### Exercise 3.2: Enable VPC Flow Logs

**Using AWS CLI:**

```bash
# Enable flow logs for a VPC
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name vpc-flow-logs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogsRole

# Enable flow logs to S3
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::my-flow-logs-bucket/
```

**Using AWS Console:**
1. VPC Dashboard → Your VPCs
2. Select VPC → Flow Logs tab
3. Create Flow Log
4. Choose destination (CloudWatch Logs or S3)

### Exercise 3.3: Query Flow Logs with CloudWatch Logs Insights

**Basic Queries:**

```sql
-- Top 10 source IPs by packet count
fields @timestamp, srcAddr, dstAddr, packets
| stats sum(packets) as packetCount by srcAddr
| sort packetCount desc
| limit 10

-- Rejected connections (potential security threats)
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter action = "REJECT"
| sort @timestamp desc

-- Traffic to specific port (e.g., SSH)
fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, bytes
| filter dstPort = 22
| sort @timestamp desc

-- Large data transfers
fields @timestamp, srcAddr, dstAddr, bytes, packets
| filter bytes > 1000000
| sort bytes desc

-- Protocol distribution
fields protocol
| stats count() by protocol
```

### Exercise 3.4: Security Analysis with Flow Logs

**Detecting Port Scans:**

```sql
-- Multiple destination ports from single source in short time
fields @timestamp, srcAddr, dstPort
| stats count_distinct(dstPort) as uniquePorts by srcAddr
| filter uniquePorts > 50
| sort uniquePorts desc
```

**Detecting Data Exfiltration:**

```sql
-- Large outbound transfers to external IPs
fields @timestamp, srcAddr, dstAddr, bytes, packets
| filter dstAddr not like /^10\./
| filter dstAddr not like /^172\.(1[6-9]|2[0-9]|3[0-1])\./
| filter dstAddr not like /^192\.168\./
| stats sum(bytes) as totalBytes by srcAddr, dstAddr
| filter totalBytes > 10000000
| sort totalBytes desc
```

**Detecting Brute Force Attempts:**

```sql
-- Multiple connection attempts to SSH/RDP
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter dstPort in [22, 3389]
| stats count() as attempts by srcAddr, dstAddr
| filter attempts > 100
| sort attempts desc
```

**Detecting C2 Communication:**

```sql
-- Regular beaconing (connection frequency analysis)
fields @timestamp, srcAddr, dstAddr, dstPort
| filter dstAddr not like /^10\./
| filter dstAddr not like /^172\.(1[6-9]|2[0-9]|3[0-1])\./
| filter dstAddr not like /^192\.168\./
| stats count() as connectionCount by bin(1h), srcAddr, dstAddr
| filter connectionCount > 10 and connectionCount < 100
```

### Exercise 3.5: Analyzing Flow Logs in S3 with Athena

**Create Athena Table:**

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flow_logs (
  version int,
  account string,
  interfaceid string,
  sourceaddress string,
  destinationaddress string,
  sourceport int,
  destinationport int,
  protocol int,
  numpackets int,
  numbytes bigint,
  starttime int,
  endtime int,
  action string,
  logstatus string
)
PARTITIONED BY (dt string)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ' '
LOCATION 's3://your-bucket-name/prefix/AWSLogs/{account_id}/vpcflowlogs/{region}/'
TBLPROPERTIES ("skip.header.line.count"="1");
```

**Query Examples:**

```sql
-- Top talkers
SELECT sourceaddress, 
       SUM(numbytes) as total_bytes,
       COUNT(*) as flow_count
FROM vpc_flow_logs
WHERE dt = '2024-02-10'
GROUP BY sourceaddress
ORDER BY total_bytes DESC
LIMIT 20;

-- Rejected traffic analysis
SELECT sourceaddress,
       destinationaddress,
       destinationport,
       protocol,
       COUNT(*) as reject_count
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND dt = '2024-02-10'
GROUP BY sourceaddress, destinationaddress, destinationport, protocol
ORDER BY reject_count DESC;

-- SSH brute force detection
SELECT sourceaddress,
       COUNT(DISTINCT destinationaddress) as target_count,
       SUM(numpackets) as total_packets
FROM vpc_flow_logs
WHERE destinationport = 22
  AND dt = '2024-02-10'
GROUP BY sourceaddress
HAVING COUNT(DISTINCT destinationaddress) > 10
ORDER BY target_count DESC;
```

### Exercise 3.6: Automated Alerting with Flow Logs

**CloudWatch Alarm for Rejected Connections:**

```bash
# Create metric filter
aws logs put-metric-filter \
  --log-group-name vpc-flow-logs \
  --filter-name RejectedConnections \
  --filter-pattern '[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action = REJECT, flowlogstatus]' \
  --metric-transformations \
    metricName=RejectedConnectionCount,metricNamespace=VPC,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name high-rejected-connections \
  --alarm-description "Alert on high number of rejected connections" \
  --metric-name RejectedConnectionCount \
  --namespace VPC \
  --statistic Sum \
  --period 300 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:SecurityAlerts
```

### Exercise 3.7: Integration with SIEM

**Shipping Flow Logs to Splunk:**

1. Configure S3 bucket for flow logs
2. Install Splunk Add-on for AWS
3. Configure inputs for S3
4. Create index for flow logs
5. Build searches and dashboards

**Sample Splunk Search:**

```spl
index=aws_vpc_flow action=REJECT
| stats count by src_ip dest_ip dest_port
| where count > 10
| table src_ip dest_ip dest_port count
| sort -count
```

**Shipping to Elasticsearch:**

```python
# Python script to parse and ship to ELK
import boto3
import json
from elasticsearch import Elasticsearch

s3 = boto3.client('s3')
es = Elasticsearch(['http://localhost:9200'])

def parse_flow_log(line):
    fields = line.split()
    return {
        'version': fields[0],
        'account_id': fields[1],
        'interface_id': fields[2],
        'src_addr': fields[3],
        'dst_addr': fields[4],
        'src_port': fields[5],
        'dst_port': fields[6],
        'protocol': fields[7],
        'packets': fields[8],
        'bytes': fields[9],
        'start': fields[10],
        'end': fields[11],
        'action': fields[12],
        'log_status': fields[13]
    }

def ingest_logs(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    for line in obj['Body'].read().decode('utf-8').split('\n'):
        if line:
            doc = parse_flow_log(line)
            es.index(index='vpc-flow-logs', body=doc)
```

---

## Part 4: Integrated Detection Lab

### Exercise 4.1: Multi-Tool Investigation

**Scenario:** You receive an alert about potential data exfiltration from a web server.

**Step 1: VPC Flow Logs Analysis**
```sql
-- Check for large outbound transfers
fields @timestamp, srcAddr, dstAddr, bytes
| filter srcAddr = "10.0.1.100"  # Web server IP
| filter bytes > 5000000
| sort @timestamp desc
```

**Step 2: Capture Live Traffic with tcpdump**
```bash
# Capture traffic from web server to suspicious IP
sudo tcpdump -i eth0 -nn 'host 10.0.1.100 and host 203.0.113.50' -w investigation.pcap
```

**Step 3: Deep Analysis with Wireshark**
1. Open investigation.pcap in Wireshark
2. Check HTTP requests: `http.request`
3. Follow TCP streams
4. Export HTTP objects
5. Identify exfiltration method

### Exercise 4.2: Building Detection Rules

**tcpdump-based Alert:**
```bash
#!/bin/bash
# Monitor for large file uploads

sudo tcpdump -i eth0 -nn 'tcp and dst port 80' -l | \
while read line; do
    size=$(echo $line | awk '{print $NF}')
    if [ "$size" -gt 10000 ]; then
        echo "ALERT: Large HTTP upload detected - $line" | \
        mail -s "Security Alert" security@company.com
    fi
done
```

**Wireshark Display Filter for IOCs:**
```
# Create filter for known malicious IPs
ip.addr in {203.0.113.50 198.51.100.25}

# Save as filter button for quick access
```

**CloudWatch Logs Alert:**
```sql
-- Custom metric for SSH from external IPs
fields @timestamp, srcAddr, dstAddr, dstPort
| filter dstPort = 22
| filter srcAddr not like /^10\./
| filter srcAddr not like /^172\.(1[6-9]|2[0-9]|3[0-1])\./
| filter srcAddr not like /^192\.168\./
| stats count() as ssh_attempts by srcAddr
| filter ssh_attempts > 5
```

### Exercise 4.3: Creating Playbooks

**Network Anomaly Response Playbook:**

1. **Initial Detection**
   - Alert triggered by monitoring system
   - Record alert details and timestamp

2. **Triage with Flow Logs**
   - Query VPC Flow Logs for affected resource
   - Identify source and destination IPs
   - Check action (ACCEPT/REJECT) and data volume

3. **Packet Capture**
   - Deploy tcpdump on affected system
   - Capture 5-10 minutes of traffic
   - Focus on suspicious connections

4. **Deep Analysis**
   - Open PCAP in Wireshark
   - Protocol analysis
   - Stream reconstruction
   - IOC extraction

5. **Containment**
   - Update security groups
   - Block malicious IPs
   - Isolate affected systems

6. **Documentation**
   - Timeline of events
   - IOCs discovered
   - Actions taken
   - Recommendations

---

## Part 5: Advanced Topics

### Exercise 5.1: Encrypted Traffic Analysis

**TLS Fingerprinting with JA3:**

While full payload analysis isn't possible with encryption, you can:
- Analyze TLS handshakes
- Create JA3 fingerprints
- Identify malware by TLS behavior
- Monitor certificate changes

**Using Wireshark:**
```
# Filter for Client Hello
ssl.handshake.type == 1

# Export TLS parameters
File → Export Packet Dissections → As CSV
```

### Exercise 5.2: Network Baseline Creation

**Establish Normal Behavior:**

```bash
# Week-long capture for baseline
sudo tcpdump -i eth0 -w baseline-$(date +%Y%m%d).pcap -G 86400 -W 7
```

**Analyze in Wireshark:**
1. Statistics → Protocol Hierarchy (note distributions)
2. Statistics → Conversations (note top talkers)
3. Statistics → Endpoints (note typical IPs)
4. Create profile for "normal" traffic

**Compare Against Baseline:**
- New protocols appearing
- Traffic volume changes
- New external connections
- Unusual port usage

### Exercise 5.3: Threat Hunting with Network Data

**Hunt Hypothesis:** Attackers are using DNS tunneling for C2

**Hunt Steps:**

1. **VPC Flow Logs:**
   ```sql
   -- High volume DNS traffic
   fields @timestamp, srcAddr, dstAddr, dstPort, packets
   | filter dstPort = 53
   | stats sum(packets) as dns_queries by srcAddr
   | filter dns_queries > 1000
   ```

2. **Packet Capture:**
   ```bash
   sudo tcpdump -i eth0 'udp port 53' -w dns_analysis.pcap
   ```

3. **Wireshark Analysis:**
   ```
   # Long DNS queries (potential tunneling)
   dns.qry.name.len > 50
   
   # High query frequency
   dns
   Statistics → I/O Graph
   ```

4. **Extract Suspicious Domains:**
   ```
   dns.qry.name
   Statistics → Conversations → Export
   ```

---

## Part 6: Lab Challenges

### Challenge 1: Investigate the Breach

**Download PCAP:** [Provide sample malware traffic PCAP]

**Tasks:**
1. Identify the initial compromise vector
2. Find the C2 server IP and domain
3. Determine what data was exfiltrated
4. Extract IOCs (IPs, domains, file hashes)
5. Create a timeline of events

**Deliverables:**
- Written report with findings
- List of IOCs in STIX format
- Wireshark display filters to detect similar activity

### Challenge 2: Build a Detection System

**Requirements:**
- Create tcpdump filters for 5 different attack types
- Build Wireshark profiles for incident response
- Design CloudWatch Log Insights queries for common threats
- Document your detection logic

**Attack Types to Cover:**
- Port scanning
- SQL injection
- Data exfiltration
- C2 beaconing
- Brute force attacks

### Challenge 3: Cloud Investigation

**Scenario:** An EC2 instance in your VPC has been communicating with a known botnet IP.

**Tasks:**
1. Query VPC Flow Logs to find affected instance
2. Identify all connections to/from malicious IP
3. Determine if data was exfiltrated
4. Find other potentially compromised instances
5. Create remediation plan

**Use:**
- CloudWatch Logs Insights
- AWS Athena queries
- VPC Flow Log analysis

---

## Best Practices

### tcpdump
- Always use `-n` flag to avoid DNS lookups (faster, prevents alerting targets)
- Rotate capture files with `-C` and `-W` for long-term monitoring
- Use specific filters to reduce capture size
- Save captures for future analysis

### Wireshark
- Create custom profiles for different investigation types
- Save frequently used filters as buttons
- Use coloring rules to highlight important traffic
- Export objects for malware analysis
- Document findings with annotations

### VPC Flow Logs
- Enable for all VPCs and critical subnets
- Use appropriate log retention based on compliance requirements
- Aggregate logs to centralized location (S3 or SIEM)
- Create baseline metrics for anomaly detection
- Automate analysis with Lambda functions

---

## Additional Resources

### Practice PCAPs
- malware-traffic-analysis.net
- netresec.com (PCAP samples)
- contagiodump.blogspot.com
- wireshark.org/sample-captures

### Learning Resources
- Wireshark University
- SANS SEC503: Network Monitoring
- AWS VPC Flow Logs documentation
- tcpdump man pages

### Tools
- NetworkMiner (passive network forensics)
- Zeek (network security monitor)
- Suricata (IDS/IPS)
- Moloch (packet capture and indexing)

---

## Lab Completion Checklist

- [ ] Performed packet capture with tcpdump
- [ ] Created advanced capture filters
- [ ] Analyzed traffic with Wireshark
- [ ] Used display filters effectively
- [ ] Followed TCP/HTTP streams
- [ ] Identified malicious traffic patterns
- [ ] Configured VPC Flow Logs
- [ ] Queried flow logs with CloudWatch Insights
- [ ] Built security detection queries
- [ ] Integrated network analysis tools
- [ ] Documented investigation methodology
- [ ] Created detection rules
- [ ] Completed at least one challenge

---

## Conclusion

Network analysis is fundamental to security detection and response. By mastering tcpdump for packet capture, Wireshark for deep protocol analysis, and AWS VPC Flow Logs for cloud visibility, you've built a comprehensive toolkit for investigating security incidents and hunting threats.

Lessons Learned:
- **Defense in depth:** Use multiple tools and data sources
- **Baseline first:** Understand normal before detecting abnormal
- **Automate detection:** Build rules and alerts based on patterns
- **Document everything:** Create playbooks and procedures
- **Keep learning:** Threat landscape constantly evolves


