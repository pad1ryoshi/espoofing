# SPF/DMARC Scanner

A fast and efficient scanner for identifying email spoofing vulnerabilities through SPF and DMARC record analysis on subdomains.

## Features

- **Multi-threaded**: Parallel execution for maximum performance
- **Precise detection**: Identifies vulnerable SPF/DMARC configurations
- **Colored output**: Clear visualization of security status
- **Detailed analysis**: Shows exactly which records are misconfigured

## Vulnerabilities Detected

### SPF (Sender Policy Framework)
- ❌ **Missing SPF record**
- ❌ **Weak policies**: `~all` (SoftFail), `+all` (Pass), `?all` (Neutral)
- ❌ **Missing `-all`**: No Hard Fail implementation
- ❌ **Misconfigured redirects**

### DMARC (Domain-based Message Authentication)
- ❌ **Missing DMARC record**
- ❌ **Policy `p=none`**: Doesn't reject suspicious emails
- ❌ **Low percentage**: `pct=0` or `pct=1`
- ❌ **Missing restrictive policies**: No `quarantine` or `reject`

## Installation

```bash
# Clone the repository
git clone https://github.com/pad1ryoshi/espoofing.git
cd espoofing

# Build the binary
go build -o espoofing espoofing.go
```

## Usage

### Basic
```bash
./espoofing subdomains.txt
```

### Advanced
```bash
./espoofing subdomains.txt 50 10
#                          ^   ^
#                              |   timeout (seconds)
#                                  threads
```

### Input file example
```
mail.example.com
subdomain1.target.com
subdomain2.target.com
app.vulnerable-site.com
```

## Output Example

```
[+] SPF/DMARC Scanner - Email Spoofing Vulnerability Checker
[+] Threads: 20, Timeout: 5s
[+] Scanning domains from: subdomains.txt
------------------------------------------------------------

[*] Domain: mail.example.com
    SPF: [VULNERABLE]
         v=spf1 include:_spf.google.com ~all
    DMARC: [NOT FOUND - VULNERABLE]
    [!] SPOOFING POSSIBLE

[*] Domain: secure.example.com
    SPF: [OK]
         v=spf1 include:_spf.google.com -all
    DMARC: [OK]
           v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `threads` | 20 | Number of concurrent threads |
| `timeout` | 5s | DNS query timeout |

## Technical Details

The scanner performs DNS TXT record lookups to:
1. **SPF Analysis**: Checks for presence and strength of SPF policies
2. **DMARC Analysis**: Validates DMARC policies and percentages
3. **Vulnerability Assessment**: Identifies exploitable configurations

### SPF Vulnerability Logic
```go
// Weak configurations detected:
- Missing SPF record
- Soft fail (~all) allows spoofing
- Pass (+all) allows any IP
- Neutral (?all) performs no check
- Missing hard fail (-all)
```

### DMARC Vulnerability Logic
```go
// Weak configurations detected:
- Missing DMARC record
- Policy "none" (p=none)
- Low enforcement percentage
- Missing quarantine/reject policies
```

## 🚨 Legal Disclaimer

This tool is intended for:
- ✅ Authorized security testing
- ✅ Bug bounty programs
- ✅ Educational purposes
- ✅ Internal security assessments

**Always ensure proper authorization before testing any domains.**
