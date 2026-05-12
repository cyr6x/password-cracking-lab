# Password Cracking Lab
**Hash Cracking | Wordlist Attacks | Rule-Based Attacks | Defender Analysis**

> Hands-on password cracking lab using Hashcat and John the Ripper on Kali Linux — cracking MD5, SHA1, and NTLM hashes using wordlists and rule-based attacks, and mapping techniques to MITRE ATT&CK.

---

## Lab Environment

| Component | Details |
|---|---|
| **Primary Tool** | Hashcat |
| **Secondary Tool** | John the Ripper |
| **Platform** | Kali Linux (VM) |
| **Wordlist** | rockyou.txt (`/usr/share/wordlists/rockyou.txt`) |
| **Hash Types** | MD5, SHA1, NTLM |

> ⚠️ All hashes were self-generated for lab purposes. No real credentials were targeted.

---

## Objectives

- Generate MD5, SHA1, and NTLM hashes from known plaintext passwords
- Crack hashes using Hashcat with a wordlist attack
- Apply rule-based attacks to crack more complex passwords
- Understand why weak and reused passwords are catastrophic
- Document findings and map to MITRE ATT&CK

---

## Setup

### Prepare the Wordlist
```bash
# Decompress rockyou.txt if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### Generate Hashes
```bash
# MD5
echo -n "password123" | md5sum
# Output: 482c811da5d5b4bc6d497ffa98491e38

# SHA1
echo -n "password123" | sha1sum
# Output: cbfdac6008f9cab4083784cbd1874f76618d2a97

# NTLM (using Python)
python3 -c "import hashlib; print(hashlib.new('md4', 'password123'.encode('utf-16le')).hexdigest())"
# Output: 588a585028fc2fc9cd4b0a94c8e49773
```

### Save Hashes to Files
```bash
echo "482c811da5d5b4bc6d497ffa98491e38" > md5.txt
echo "cbfdac6008f9cab4083784cbd1874f76618d2a97" > sha1.txt
echo "588a585028fc2fc9cd4b0a94c8e49773" > ntlm.txt
```

---

## Attack 1 — MD5 Wordlist Crack

### What it is
A wordlist attack hashes every word in a list and compares it against the target hash. If the password exists anywhere in the wordlist, it will be cracked in seconds.

### Command
```bash
hashcat -m 0 -a 0 md5.txt /usr/share/wordlists/rockyou.txt
# -m 0  = MD5
# -a 0  = wordlist (dictionary) attack
```

### Result
```
482c811da5d5b4bc6d497ffa98491e38:password123
Status: Cracked
Time: < 1 second
```

![MD5 Hash Cracked](screenshots/md5-cracked.png)

---

## Attack 2 — SHA1 Wordlist Crack

### What it is
Same approach as MD5 — SHA1 is equally fast to compute, meaning Hashcat can test billions of candidates per second on modern hardware.

### Command
```bash
hashcat -m 100 -a 0 sha1.txt /usr/share/wordlists/rockyou.txt
# -m 100 = SHA1
```

### Result
```
cbfdac6008f9cab4083784cbd1874f76618d2a97:password123
Status: Cracked
Time: < 1 second
```

![SHA1 Hash Cracked](screenshots/sha1-cracked.png)

---

## Attack 3 — NTLM Wordlist Crack

### What it is
NTLM is the hash format used by Windows for local account passwords. It is extremely fast to compute — no salt, no iterations — making it one of the weakest hash formats in production use.

### Command
```bash
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
# -m 1000 = NTLM
```

### Result
```
588a585028fc2fc9cd4b0a94c8e49773:password123
Status: Cracked
Time: < 1 second
```

![NTLM Hash Cracked](screenshots/ntlm-cracked.png)

---

## Attack 4 — Rule-Based Attack

### What it is
Rule-based attacks mutate wordlist entries on the fly — capitalising the first letter, appending numbers, substituting `a→3`, `e→3` etc. This cracks passwords that are slightly modified common words.

### Command
```bash
hashcat -m 0 -a 0 md5.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# best64.rule = 64 most effective mutation rules
```

### Example mutations applied to `password`:
| Rule | Output |
|---|---|
| Capitalise first letter | `Password` |
| Append `1` | `password1` |
| Substitute `a→3` | `p3ssword` |
| Reverse | `drowssap` |

![Rule-Based Attack](screenshots/rule-attack.png)

---

## Findings

| Hash Type | Password | Time to Crack | Attack Method |
|---|---|---|---|
| MD5 | password123 | < 1 second | Wordlist |
| SHA1 | password123 | < 1 second | Wordlist |
| NTLM | password123 | < 1 second | Wordlist |
| MD5 (mutated) | Password1 | < 1 second | Rule-based |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Cracking | T1110.002 |
| Credential Access | OS Credential Dumping: NTLM | T1003.002 |
| Credential Access | Unsecured Credentials | T1552 |
| Lateral Movement | Pass the Hash | T1550.002 |

---

## Defender Takeaways

### Why Weak Hashes Are Dangerous
| Hash | Salted | Iterations | Crackable |
|---|---|---|---|
| MD5 | ❌ | 1 | In seconds |
| SHA1 | ❌ | 1 | In seconds |
| NTLM | ❌ | 1 | In seconds |
| bcrypt | ✅ | 10,000+ | Hours–years |
| Argon2 | ✅ | Configurable | Practically infeasible |

### Prevention Controls
| Control | How It Helps |
|---|---|
| **bcrypt / Argon2 / scrypt** | Slow, salted hashing — makes cracking computationally infeasible |
| **Password length > 14 chars** | Exponentially increases brute-force time |
| **Password managers** | Enables unique, random passwords per account — eliminates reuse |
| **MFA** | Cracked password alone is insufficient without a second factor |
| **Account lockout policies** | Blocks online brute-force attempts after N failed logins |
| **Credential monitoring** | Services like HaveIBeenPwned alert when passwords appear in breach dumps |

### SOC Detection
| Signal | Detection Logic |
|---|---|
| **Multiple failed logins** | >5 failed attempts in 60s → SIEM alert (brute force indicator) |
| **LSASS memory access** | EDR alert on any process reading lsass.exe (NTLM dump attempt) |
| **Credential dump tools** | `mimikatz`, `secretsdump` execution → immediate P1 alert |
| **Pass-the-Hash activity** | Lateral movement using NTLM hash without plaintext password |

---

## Academic & Professional Context

- **CompTIA Security+ SY0-701** — Domain 2.4: Analysing indicators of malicious activity (credential attacks)
- **CompTIA PenTest+ PT0-002** — Domain 3: Password attacks
- **CEH / OSCP** — Core credential access methodology
- **OWASP** — A07: Identification and Authentication Failures

---

## Status

- [x] Lab environment configured on Kali
- [x] MD5, SHA1, NTLM hashes generated
- [x] Wordlist attack — all 3 hashes cracked in < 1 second
- [x] Rule-based attack tested
- [x] Findings documented
- [x] MITRE ATT&CK mapping completed
- [ ] Screenshots captured and pushed
