# Cisco FTD Security Assessment Report

**Input file:** `example-ftd-config.cfg`  
**Hostname:** `FTD-EDGE-PROD`  
**Version:** `ASA 9.14(1)`  
**Assessment mode:** `FILE MODE`  
**Generated:** `2026-03-27T15:23:10Z`

---

## Executive Summary

This firewall configuration has multiple **critical exposures** that create immediate attack paths from external and internal networks.

- **13 HIGH** findings
- **4 MEDIUM** findings
- **1 LOW** finding

The highest-risk issues are:
1. `permit ip any any` on inbound ACL
2. Public static NAT of internal payment server
3. Weak VPN cryptography (DES / 3DES / MD5 / DH group 2)
4. Unrestricted SSH access from `0.0.0.0/0` on OUTSIDE
5. Telnet enabled and permitted via ACL

---

## Finding Breakdown

### HIGH (13)

| Category | Check | Target | Why it matters |
|---|---|---|---|
| Access Control | Telnet Permitted in ACL | ACL-INBOUND | Cleartext admin protocol exposed on inbound rule |
| Access Control | Overly Permissive Rule | ACL-INBOUND | `permit ip any any` disables meaningful filtering |
| Access Control | Overly Permissive Rule | ACL-INTERNAL | `permit icmp any any` allows unrestricted probing |
| NAT | Internal Host Exposed to Outside | OBJ-PAYMENT-SERVER | Payment server directly reachable from internet |
| VPN Crypto | Weak Encryption Algorithm | IPSEC proposal SET-WEAK | DES is broken and decryptable |
| VPN Crypto | Weak Integrity Algorithm | IPSEC proposal SET-WEAK | MD5 allows collision-based forgery |
| VPN Crypto | Weak IKEv2 Encryption | IKEv2 policy 1 | 3DES is deprecated and weak |
| VPN Crypto | Weak IKEv2 Integrity | IKEv2 policy 1 | MD5 in IKE negotiation is insecure |
| VPN Crypto | Weak Diffie-Hellman Group | IKEv2 policy 1 | DH group 2 (1024-bit) is factorable |
| Logging | Logging Disabled | Global | No `logging enable` => low visibility for incidents |
| Management Access | Unrestricted SSH Access | SSH on OUTSIDE | Brute-force and credential attacks from internet |
| SNMP | Default SNMP Community String | `public` | Trivial enumeration and possible abuse |
| Management Access | Telnet Enabled | Telnet on INSIDE | Credentials exposed in plaintext |

### MEDIUM (4)

| Category | Check | Target |
|---|---|---|
| Access Control | Unrestricted ICMP | ACL-INTERNAL |
| SNMP | SNMPv2c Only | SNMP config |
| NTP | Unauthenticated NTP | 1.1.1.1 |
| Interfaces | Security Level 0 on Non-Outside Interface | GigabitEthernet0/1 (INSIDE) |

### LOW (1)

| Category | Check | Target |
|---|---|---|
| Hygiene | Stale Object Group | GRP-LEGACY-SERVERS |

---

## Priority Remediation Plan

### Immediate (0-7 days)

1. Remove direct internet exposure of payment server:

```bash
object network OBJ-PAYMENT-SERVER
 no nat (INSIDE,OUTSIDE) static 203.0.113.3
```

2. Remove over-permissive inbound ACLs:

```bash
no access-list ACL-INBOUND Extended permit ip any any
no access-list ACL-INTERNAL Extended permit icmp any any
```

3. Remove telnet policy/rules:

```bash
no access-list ACL-INBOUND Extended permit tcp any object OBJ-PAYMENT-SERVER eq 23
no telnet 10.1.10.0 255.255.255.0 INSIDE
```

4. Restrict SSH management:

```bash
no ssh 0.0.0.0 0.0.0.0 OUTSIDE
ssh 192.168.1.0 255.255.255.0 MGMT
```

5. Remove weak crypto suite:

```bash
no crypto ipsec ikev2 ipsec-proposal SET-WEAK
no crypto ikev2 policy 1
```

---

### Near-term (8-30 days)

- Enable logging and central syslog:

```bash
logging enable
logging buffered informational
logging trap informational
logging host INSIDE <syslog-server-ip>
```

- Migrate SNMPv2c to SNMPv3:

```bash
no snmp-server community public
snmp-server group FW-MONITORS v3 priv
snmp-server user snmpAdmin FW-MONITORS v3 auth sha <auth-key> priv aes 256 <priv-key>
```

- Add authenticated NTP:

```bash
ntp authenticate
ntp authentication-key 1 md5 <ntp-key>
ntp trusted-key 1
no ntp server 1.1.1.1
ntp server 1.1.1.1 key 1
```

---

### Validation Checklist

- [ ] Payment server no longer internet-reachable
- [ ] No `permit ip any any` in active ACLs
- [ ] Telnet fully removed
- [ ] SSH only from management subnet
- [ ] VPN negotiates only strong suites (AES-256 / SHA-256+ / DH19+)
- [ ] Logging visible in centralized syslog/SIEM
- [ ] SNMPv3 operational; no v2c communities
- [ ] NTP synchronized with authentication enabled

---

## Generated Artifacts

- **PDF report:** `FTD-EDGE-PROD_Security_Report.pdf`
- **Markdown report:** `ASSESSMENT_example-ftd-config.md`
- **Source config analyzed:** `example-ftd-config.cfg`
