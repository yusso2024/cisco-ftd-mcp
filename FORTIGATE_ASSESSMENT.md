# FortiGate Security Assessment

**Config source:** `example-fortigate-config.conf`  
**Device:** `FGT-BRANCH-EDGE-01`  
**FortiOS version:** `7.0.5`  
**Artifacts generated:**
- `FORTIGATE_Security_Report.pdf`

---

## Executive Summary

Assessment result for this FortiGate configuration:

- **12 HIGH** findings
- **3 MEDIUM** findings
- **1 LOW** finding

The configuration currently has externally exposed management, permissive firewall policies, weak VPN crypto, and disabled centralized logging.

---

## Top Critical Risks

1. **Allow-any-any policy** in `config firewall policy` (`set srcaddr "all"`, `set dstaddr "all"`, `set service "ALL"`).
2. **Inbound telnet policy** to internal payment server (`set service "TELNET"`).
3. **Public VIP exposure** of internal host (`VIP-PAYMENT: 198.51.100.11 -> 10.20.10.50`).
4. **Weak IPsec/IKE crypto** (`3des-md5`, `des`, `md5`, `dhgrp 2`).
5. **WAN management exposure** (`allowaccess ping https ssh http telnet` on `wan1`).

---

## Full Finding Summary

### HIGH
- Telnet permitted in firewall policy
- Overly permissive all/any firewall policy
- Overly permissive internal ICMP policy
- Internal host exposed by static VIP
- Weak IPsec encryption algorithm (DES)
- Weak IPsec integrity algorithm (MD5)
- Weak IKEv2 encryption (3DES)
- Weak IKEv2 integrity (MD5)
- Weak Diffie-Hellman group (2)
- Logging disabled (syslog disabled)
- Unrestricted SSH/HTTP management access on WAN
- Default SNMP community (`public`)

### MEDIUM
- Unrestricted ICMP allowance
- SNMPv2c-only style config
- Potentially outdated FortiOS baseline (7.0.5)

### LOW
- Stale/legacy address group (`LEGACY_UNUSED`)

---

## Recommended 30-60-90 Plan

### 0-30 days (immediate)
- Remove all-any firewall policy.
- Remove telnet service policy to payment host.
- Restrict `wan1` `allowaccess` to minimum (remove `ssh`, `http`, `telnet`).
- Disable public VIP exposure of payment server unless strictly required.
- Remove weak VPN proposals and DH group 2.
- Enable syslog forwarding.

### 31-60 days
- Migrate SNMP to SNMPv3 and remove `public`.
- Add authenticated NTP strategy.
- Review policy-by-policy least privilege with application-specific services only.

### 61-90 days
- Upgrade to a current FortiOS supported train per Fortinet PSIRT guidance.
- Remove legacy/unused objects and groups.
- Establish recurring monthly configuration assessment + report publication.

---

## Suggested Command Direction (high-level)

```bash
# firewall policy hardening
config firewall policy
  delete 1   # ALLOW-ANY-ANY
  delete 2   # ALLOW-TELNET-TO-PAYMENT
end

# WAN management lock-down
config system interface
  edit "wan1"
    set allowaccess ping
  next
end

# remove risky VIP exposure (if not business-required)
config firewall vip
  delete "VIP-PAYMENT"
end

# strengthen VPN crypto
config vpn ipsec phase1-interface
  edit "LEGACY-TUNNEL"
    set proposal aes256-sha256
    set dhgrp 14
  next
end

# enable centralized logging
config log syslogd setting
  set status enable
  set server <syslog-ip>
end

# remove default SNMP community
config system snmp community
  delete 1
end
```

> Validate in lab/change window and include rollback before production deployment.
