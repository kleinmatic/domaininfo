# Domain Lookup Tool

## Project Overview

This is a command-line tool that looks up comprehensive hosting and registration information for domain names. It combines multiple DNS and WHOIS queries to provide a complete picture of a domain's infrastructure.

## What It Does

The tool performs the following lookups for any given domain:

1. **IP Address** - Resolves the domain to its IP address
2. **Nameserver** - Identifies the DNS hosting provider (e.g., Cloudflare, Route 53, NS1)
3. **Registrar** - Shows who manages the domain registration (via domain WHOIS)
4. **Hosting** - Identifies the hosting company (via IP WHOIS lookup on the netblock owner)
5. **CDN Detection** - Automatically detects if the site uses a CDN service

## Key Features

### Domain Normalization & Root Domain Extraction
- **Hostname vs Root Domain**: The tool correctly distinguishes between the target hostname (used for IP/Hosting) and the registered root domain (used for Registrar/NS).
- **Multi-part TLD Support**: Includes a manual list of common multi-part TLDs (e.g., `.co.uk`, `.com.au`) to correctly identify the root domain.
- **Robust URL Cleaning**: Strips `http://`, `https://`, paths, query strings, fragments, and ports consistently.
- **Input Validation**: Validates that inputs are valid domain names (must contain at least one dot, valid characters only).

### Redirect Detection
- **Cross-Domain Redirect Detection**: Automatically detects HTTP 3xx redirects to different domains.
- **Smart Filtering**: Only reports redirects when the target domain differs from the original (ignores protocol-only changes like http → https).
- **Non-Following Behavior**: The tool analyzes the domain you provide, not the redirect target, but warns you about cross-domain redirects.

### Bulk Lookup & Concurrency
- **CSV Output**: Supports generating structured CSV reports for multiple domains.
- **Threading**: Uses `concurrent.futures.ThreadPoolExecutor` to process bulk lookups in parallel (default 10 threads).
- **Flexible Input**: Accepts domains via:
    - Single positional argument
    - Multiple positional arguments
    - Piped input (stdin)
    - File input (`--input`)

### Nameserver Detection
- Uses `dig` to query NS records
- Includes mapping of common nameserver providers (Cloudflare, Route 53, NS1 (IBM), etc.)
- Falls back to WHOIS lookup on the nameserver domain for unknown providers

### CDN Detection
The tool automatically identifies when a domain is using a CDN, including:
- Cloudflare
- Fastly
- Akamai
- Amazon CloudFront
- Incapsula/Imperva
- Sucuri
- StackPath
- KeyCDN
- BunnyCDN
- EdgeCast

When a CDN is detected, "(CDN)" is appended to the hosting information.

### CDN Limitation
**Important**: When a site uses a CDN (like Cloudflare, Fastly, Akamai), the IP lookup shows the CDN's edge servers, not the origin hosting. It's difficult to determine the actual origin host without:
- Checking MX records (mail servers often aren't CDN-protected)
- Subdomain enumeration (mail., ftp., direct., etc. might not be CDN-protected)
- Historical DNS data (requires paid services like SecurityTrails)
- SSL/TLS certificate inspection for additional domains

The tool correctly identifies this situation by marking the provider as "(CDN)".

## Usage

```bash
# Single Domain (Human Readable)
./domaininfo.py example.com

# Multiple Domains (CSV to stdout)
./domaininfo.py google.com wordpress.org

# Piped Input (CSV to stdout)
cat domains.txt | ./domaininfo.py

# File Input (CSV to file)
./domaininfo.py --input domains.txt --output report.csv
```

## Sample Output

### Single Mode
```
Looking up: bit.ly
Root Domain: bit.ly
Note: This domain redirects to https://bitly.com/
IP Address: 67.199.248.10
Nameserver: Google Domains
Registrar: Libyan Spider Network (int)
Hosting: Bitly Inc
```

### Bulk Mode (CSV)
```csv
hostname,root_domain,redirect_target,ip,nameserver,registrar,hosting,is_cdn,error
bit.ly,bit.ly,https://bitly.com/,67.199.248.10,Google Domains,Libyan Spider Network (int),Bitly Inc,False,
ebay.com,ebay.com,,23.206.172.57,NS1 (IBM),MarkMonitor Inc.,Akamai Technologies Inc.,True,
```

## Dependencies

The tool requires these command-line utilities:
- `whois` - For domain and IP WHOIS queries
  - Install on macOS: `brew install whois`
- `dig` - For DNS lookups (usually pre-installed on macOS/Linux)
- Python 3 - The script is written in Python 3

## Technical Implementation

### DNS Resolution
Uses Python's `socket.gethostbyname()` for IP address resolution.

### WHOIS Queries
- **Domain WHOIS**: Queries registrar information from domain registries
- **IP WHOIS**: Queries Regional Internet Registries (ARIN, RIPE, APNIC, etc.) for netblock ownership

### Parsing Strategy
The tool handles different WHOIS formats from various registries by trying multiple field patterns:
- OrgName, org-name, orgname
- Organization, organisation
- owner, Owner
- descr, Descr
- Registrar, registrar

## Design Decisions

1.  **Hostname vs Root Domain**: Essential for accurate lookups. Subdomains (like `shop.example.com`) need their specific IP checked for hosting, but the root domain (`example.com`) must be used for Registrar and NS lookups.
2.  **Threading**: Network lookups are latency-bound. Threading significantly improves performance for bulk lookups without complex async code.
3.  **Smart Input Handling**: The tool automatically detects if it's receiving one domain or many (via args or pipe) and switches output formats (Text vs CSV) accordingly to be most helpful.
4.  **Dependency-Free TLD Parsing**: Uses a lightweight manual list for multi-part TLDs to avoid heavy external dependencies like `tldextract`.

## Files

- `domaininfo.py` - Main executable script
- `AGENTS.md` - This file, project context for future sessions

## Future Enhancement Ideas

If you want to extend this tool:
- Add MX record lookup to help identify origin hosting behind CDNs
- Add subdomain enumeration to find non-CDN-protected hosts
- JSON output format for scripting
- Integration with DNS history APIs (SecurityTrails, etc.)
- HTTP header inspection for additional CDN detection
- Certificate transparency log queries for subdomain discovery

