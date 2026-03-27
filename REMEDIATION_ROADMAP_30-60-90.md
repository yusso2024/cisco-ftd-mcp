## FTD-EDGE-FW01 — 30-60-90 Day Remediation Roadmap

Assessment baseline: **16 HIGH / 5 MEDIUM / 1 LOW**

---

## 0-30 Days (Immediate Risk Reduction)

### 1) Remove internet exposure of internal DB
- Remove static NAT for `OBJ-DBSERVER` (`nat (INSIDE,OUTSIDE) static 203.0.113.50`)

### 2) Remove over-permissive ACL rules
- Remove:
  - `access-list ACL-INSIDE-OUT extended permit ip any any`
  - `access-list ACL-DMZ-IN extended permit tcp any any eq 23`
  - `access-list ACL-OUTSIDE-IN extended permit icmp any any`
- Replace ICMP rule with limited ICMP types only (echo-reply, unreachable, time-exceeded)

### 3) Lock down management plane
- Remove unrestricted management access:
  - `ssh 0.0.0.0 0.0.0.0 INSIDE`
  - `http 0.0.0.0 0.0.0.0 INSIDE`
  - `telnet 10.10.1.0 255.255.255.0 INSIDE`
- Keep management only from MGMT subnet.

### 4) Remove weak VPN crypto
- Remove weak IPsec proposal:
  - `crypto ipsec ikev2 ipsec-proposal PROP-DES-LEGACY`
- Remove weak IKEv2 policy:
  - `crypto ikev2 policy 99` (DES / MD5 / DH2)

### 5) Enable centralized logging
- Add syslog target:
  - `logging host INSIDE <syslog-ip>`
- Raise levels:
  - `logging buffered informational`
  - `logging trap informational`

---

## 31-60 Days (Hardening and Control Maturity)

### 1) SNMP migration
- Remove default communities:
  - `no snmp-server community public`
  - `no snmp-server community private`
- Migrate to SNMPv3 with authPriv.

### 2) NTP authentication
- Implement authenticated NTP:
  - `ntp authenticate`
  - `ntp authentication-key ...`
  - `ntp trusted-key ...`
  - `ntp server ... key ...`

### 3) Remote Access VPN session controls
- Add:
  - `vpn-idle-timeout 30`
  - `vpn-session-timeout 480`

### 4) Restrict DMZ-to-DB traffic to app ports only
- Replace object-to-object `permit ip` with explicit port allow (e.g., `eq 3306`)

### 5) Post-change validation cadence
- Re-run full assessment after each policy batch.
- Keep changes in small windows with rollback points.

---

## 61-90 Days (Sustainment / Audit Readiness)

### 1) Config hygiene cleanup
- Remove stale object groups like `DG-LEGACY-HOSTS` after reference verification.

### 2) Baseline to standards
- Map controls to CIS/NIST firewall guidance and maintain evidence.

### 3) Operational runbooks
- Document break-glass access, rollback plans, and incident-response logging workflow.

### 4) Continuous assessment schedule
- Weekly assessment run, monthly PDF report, track risk trend.

### 5) Audit evidence package
- Maintain report history, change tickets, and before/after diffs.

---

## Prioritized CLI Change Plan (Condensed)

```bash
! Day 1
object network OBJ-DBSERVER
 no nat (INSIDE,OUTSIDE) static 203.0.113.50

no access-list ACL-INSIDE-OUT extended permit ip any any
no access-list ACL-DMZ-IN extended permit tcp any any eq 23
no access-list ACL-OUTSIDE-IN extended permit icmp any any
access-list ACL-OUTSIDE-IN extended permit icmp any any echo-reply
access-list ACL-OUTSIDE-IN extended permit icmp any any unreachable
access-list ACL-OUTSIDE-IN extended permit icmp any any time-exceeded

! Day 2-3
no ssh 0.0.0.0 0.0.0.0 INSIDE
no http 0.0.0.0 0.0.0.0 INSIDE
no telnet 10.10.1.0 255.255.255.0 INSIDE

! Day 4-7
no crypto ipsec ikev2 ipsec-proposal PROP-DES-LEGACY
no crypto ikev2 policy 99

! Day 7-14
logging host INSIDE 10.10.1.100
logging buffered informational
logging trap informational

! Day 14-30
snmp-server group FW-MONITORS v3 priv
snmp-server user snmpAdmin FW-MONITORS v3 auth sha <auth-key> priv aes 256 <priv-key>
no snmp-server community public
no snmp-server community private

! Day 30-60
ntp authenticate
ntp authentication-key 1 md5 <ntp-key>
ntp trusted-key 1
no ntp server 129.6.15.28
no ntp server 129.6.15.29
ntp server 129.6.15.28 key 1
ntp server 129.6.15.29 key 1

group-policy GP-ANYCONNECT attributes
 vpn-idle-timeout 30
 vpn-session-timeout 480

no access-list ACL-DMZ-IN extended permit ip object OBJ-WEBSERVER object OBJ-DBSERVER
access-list ACL-DMZ-IN extended permit tcp object OBJ-WEBSERVER object OBJ-DBSERVER eq 3306
```

---

## Final Validation Checklist

- DB host no longer reachable from outside
- VPN tunnels up using strong crypto only
- SSH/ASDM reachable only from MGMT subnet
- Telnet fully disabled
- Syslog events flowing to central collector
- SNMPv3 working; v2c communities removed
- Authenticated NTP in sync
- Assessment rerun shows elimination of HIGH findings targeted in 0-30 day window
