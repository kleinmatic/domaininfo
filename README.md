# Domain Lookup Tool

A command-line utility to identify domain registrars, nameservers, and hosting providers for any domain name.

## Quick Start
 
 ```bash
 # Single domain
 ./domaininfo.py example.com
 
 # Multiple domains (outputs CSV)
 ./domaininfo.py google.com wordpress.org
 ```
 
 ## What It Shows
 
 - **IP Address** - The resolved IP address
 - **Nameserver** - DNS hosting provider (Cloudflare, Route 53, etc.)
 - **Registrar** - Domain registrar (GoDaddy, Namecheap, etc.)
 - **Hosting** - Web hosting provider (with CDN detection)
 - **Redirect Detection** - Warns if domain redirects to a different domain
 
 ## Advanced Usage
 
 ### Bulk Lookup
 
 You can process a list of domains from a file:
 
 ```bash
 ./domaininfo.py --input domains.txt --output report.csv
 ```
 
 Or pipe domains directly into the tool:
 
 ```bash
 cat domains.txt | ./domaininfo.py > report.csv
 ```
 
 ### Threading
 
 By default, bulk operations use 10 concurrent threads. You can adjust this:
 
 ```bash
 ./domaininfo.py --input large_list.txt --threads 50
 ```
 
 ## Example Output
 
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
 
 ### Invalid Input
 ```
 $ ./domaininfo.py example
 Error: 'example' is not a valid domain name.
 Usage: domaininfo.py <domain>
 Example: domaininfo.py example.com
 ```
 
 ## Requirements
 
 - Python 3
 - `whois` command (`brew install whois` on macOS)
 - `dig` command (usually pre-installed)
 
 ## Features
 
 ### CDN Detection
 
 The tool automatically detects when a site uses a CDN like Cloudflare, Fastly, or Akamai, and marks it with "(CDN)".
 
 **Note**: When a CDN is detected, the hosting information shows the CDN's infrastructure, not the origin servers.
 
 ### Redirect Detection
 
 The tool checks for HTTP redirects and warns you when a domain redirects to a **different domain**. Protocol-only changes (http → https) on the same domain are ignored.
 
 ### Input Validation
 
 The tool validates domain names before processing. Inputs must:
 - Contain at least one dot (e.g., `example.com`)
 - Use only valid characters (alphanumeric, dots, hyphens)
 - Not be just a single word without a TLD
 
 ## Installation
 
 1. Make the script executable:
    ```bash
    chmod +x domaininfo.py
    ```
 
 2. Run it:
    ```bash
    ./domaininfo.py <domain>
    ```
 
 3. (Optional) Add to your PATH for system-wide access
 
 ## See Also
 
 See `AGENTS.md` for detailed technical documentation and project context.
