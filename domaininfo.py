#!/usr/bin/env python3
"""
Look up a domain name and identify its registrar and hosting company.
Combines domain WHOIS, DNS lookup, and IP WHOIS data.
Supports single domain lookup or bulk lookup from a file.
"""

import sys
import socket
import subprocess
import re
import argparse
import csv
import json
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Optional


# Compiled regex patterns
HTTP_PATTERN = re.compile(r'^https?://')
WWW_PATTERN = re.compile(r'^www\.')
PORT_PATTERN = re.compile(r':\d+$')
WHOIS_REGISTRAR_PATTERNS = [
    re.compile(r'(?:Registrar):\s*(.+)', re.IGNORECASE),
    re.compile(r'(?:registrar):\s*(.+)', re.IGNORECASE),
]
WHOIS_ORG_PATTERNS = [
    re.compile(r'(?:OrgName|org-name|orgname):\s*(.+)', re.IGNORECASE),
    re.compile(r'(?:Organization|organisation):\s*(.+)', re.IGNORECASE),
    re.compile(r'(?:owner|Owner):\s*(.+)', re.IGNORECASE),
    re.compile(r'(?:descr|Descr):\s*(.+)', re.IGNORECASE),
]

# Common multi-part TLDs
MULTI_PART_TLDS = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'net.au', 'org.au', 'edu.au',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp',
    'co.nz', 'org.nz',
    'co.za',
    'com.br',
    'com.sg',
}


def clean_domain(domain: str) -> str:
    """
    Clean up domain string.
    Removes http(s)://, paths, query strings, fragments, and ports.
    Keeps subdomains (including www).
    """
    if not domain:
        return ""
    
    # Remove http(s)://
    domain = HTTP_PATTERN.sub('', domain)
    
    # Remove path, query string, fragment (split by /, ?, #)
    # We split by the first occurrence of any of these
    domain = re.split(r'[/?#]', domain)[0]
    
    # Remove port if present (e.g. example.com:8080)
    domain = PORT_PATTERN.sub('', domain)
    
    return domain.strip()


def get_registered_domain(hostname: str) -> str:
    """
    Extract the registered domain (SLD+TLD) from a hostname.
    e.g. shop.example.co.uk -> example.co.uk
    """
    # Remove www. for the purpose of finding the root
    hostname_no_www = WWW_PATTERN.sub('', hostname)
    
    parts = hostname_no_www.split('.')
    
    if len(parts) <= 2:
        return hostname_no_www
        
    # Check last two parts for multi-part TLD
    last_two = '.'.join(parts[-2:])
    if last_two in MULTI_PART_TLDS:
        if len(parts) >= 3:
            return '.'.join(parts[-3:])
            
    return '.'.join(parts[-2:])


def is_valid_domain(domain: str) -> bool:
    """
    Check if a domain looks valid (has at least one dot and valid characters).
    Returns True if valid, False otherwise.
    """
    if not domain:
        return False
    
    # Must contain at least one dot (e.g., example.com)
    if '.' not in domain:
        return False
    
    # Basic character validation (alphanumeric, dots, hyphens)
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False
    
    # Must not start or end with a dot or hyphen
    if domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False
    
    # Each part between dots should not be empty
    parts = domain.split('.')
    if any(not part for part in parts):
        return False
    
    return True


def check_redirect(domain: str, timeout: int = 10) -> Optional[str]:
    """
    Check if the domain redirects (3xx) to a *different* domain.
    Returns the target URL if it redirects to a different domain, otherwise None.
    """
    url = f"http://{domain}"
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; DomainLookupTool/1.0)'},
            method='HEAD'
        )
        # Custom handler to stop at the first redirect
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        opener.open(req, timeout=timeout)
        return None
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            location = e.headers.get('Location')
            if not location:
                return None
            # Parse target URL
            parsed = urllib.parse.urlparse(location)
            target_host = parsed.hostname or ''
            # If relative redirect (no hostname), treat as same domain
            if not target_host:
                return None
            # Normalize domains (lowercase, strip leading www.)
            def norm(d):
                return d.lower().lstrip('www.')
            if norm(target_host) != norm(domain):
                return location
            return None
        return None
    except Exception:
        return None


def get_ip_address(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def get_registrar_info(root_domain: str) -> Optional[str]:
    """Query WHOIS for root domain and extract registrar info."""
    try:
        result = subprocess.run(
            ['whois', root_domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        whois_output = result.stdout

        for pattern in WHOIS_REGISTRAR_PATTERNS:
            match = pattern.search(whois_output)
            if match:
                registrar = match.group(1).strip()
                if registrar and not registrar.startswith('---'):
                    return registrar

        return None

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


def get_nameserver_info(root_domain: str) -> Optional[str]:
    """Get nameserver info for root domain."""
    try:
        # Get nameservers using dig
        result = subprocess.run(
            ['dig', '+short', 'NS', root_domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0 or not result.stdout.strip():
            return None

        # Get the first nameserver
        nameservers = result.stdout.strip().split('\n')
        if not nameservers:
            return None

        first_ns = nameservers[0].rstrip('.')

        # Common nameserver providers mapping
        ns_providers = {
            'cloudflare': 'Cloudflare, Inc.',
            'awsdns': 'Amazon Route 53',
            'nsone': 'NS1 (IBM)',
            'ultradns': 'UltraDNS',
            'dnsmadeeasy': 'DNS Made Easy',
            'dnsimple': 'DNSimple',
            'he.net': 'Hurricane Electric',
            'googledomains': 'Google Domains',
            'azure-dns': 'Microsoft Azure DNS',
            'linode': 'Linode',
            'digitalocean': 'DigitalOcean',
            'domaincontrol': 'GoDaddy',
            'registrar-servers': 'Namecheap',
        }

        # Check if nameserver matches known providers
        ns_lower = first_ns.lower()
        for key, provider in ns_providers.items():
            if key in ns_lower:
                return provider

        # If no match, try to extract domain from nameserver and do WHOIS
        # Use our smart domain extractor to avoid querying TLDs
        ns_root_domain = get_registered_domain(first_ns)
        
        # Do WHOIS on the nameserver domain
        whois_result = subprocess.run(
            ['whois', ns_root_domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        if whois_result.returncode == 0:
            whois_output = whois_result.stdout
            for pattern in WHOIS_ORG_PATTERNS:
                match = pattern.search(whois_output)
                if match:
                    org_name = match.group(1).strip()
                    if org_name and not org_name.startswith('---'):
                        return org_name

        return first_ns  # Return the nameserver itself if we can't determine provider

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


def is_cdn(hosting_name: str) -> bool:
    """Check if the hosting provider is a known CDN."""
    if not hosting_name:
        return False

    hosting_lower = hosting_name.lower()
    cdn_providers = [
        'cloudflare',
        'fastly',
        'akamai',
        'cloudfront',
        'amazon cloudfront',
        'incapsula',
        'imperva',
        'sucuri',
        'stackpath',
        'keycdn',
        'bunny',
        'edgecast',
    ]

    for cdn in cdn_providers:
        if cdn in hosting_lower:
            return True

    return False


def get_hosting_info(ip: str) -> Optional[str]:
    """Query WHOIS for IP and extract organization/hosting info."""
    try:
        result = subprocess.run(
            ['whois', ip],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        whois_output = result.stdout.decode('utf-8', errors='ignore')

        for pattern in WHOIS_ORG_PATTERNS:
            match = pattern.search(whois_output)
            if match:
                org_name = match.group(1).strip()
                # Skip generic/unhelpful entries
                if org_name and not org_name.startswith('---'):
                    return org_name

        return None

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


def analyze_domain(raw_input: str, check_redirects: bool = True, timeout: int = 10, verbose: bool = False) -> Dict:
    """
    Perform full analysis on a domain.
    Returns a dictionary with the results.
    """
    # 1. Clean the input to get the Hostname (used for IP/Hosting)
    hostname = clean_domain(raw_input)
    
    # Validate domain
    if not is_valid_domain(hostname):
        return {
            'original_input': raw_input,
            'hostname': hostname,
            'root_domain': '',
            'redirect_target': None,
            'ip': None,
            'nameserver': None,
            'registrar': None,
            'hosting': None,
            'is_cdn': False,
            'error': f"Invalid domain name: '{hostname}'"
        }
    
    # 2. Extract the Root Domain (used for Registrar/NS)
    root_domain = get_registered_domain(hostname)
    
    result = {
        'original_input': raw_input,
        'hostname': hostname,
        'root_domain': root_domain,
        'redirect_target': None,
        'ip': None,
        'nameserver': None,
        'registrar': None,
        'hosting': None,
        'is_cdn': False,
        'error': None
    }

    # Check for redirects
    if check_redirects:
        if verbose:
            print(f"[VERBOSE] Checking redirects for {hostname}...", file=sys.stderr)
        result['redirect_target'] = check_redirect(hostname, timeout=timeout)

    # Get IP address (uses Hostname)
    if verbose:
        print(f"[VERBOSE] Resolving IP for {hostname}...", file=sys.stderr)
    ip = get_ip_address(hostname)
    if not ip:
        result['error'] = f"Could not resolve domain '{hostname}'"
        return result
    
    result['ip'] = ip

    # Get nameserver info (uses Root Domain)
    if verbose:
        print(f"[VERBOSE] Running: dig +short NS {root_domain}", file=sys.stderr)
    result['nameserver'] = get_nameserver_info(root_domain)

    # Get registrar info (uses Root Domain)
    if verbose:
        print(f"[VERBOSE] Running: whois {root_domain}", file=sys.stderr)
    result['registrar'] = get_registrar_info(root_domain)

    # Get hosting info from WHOIS (uses IP)
    if verbose:
        print(f"[VERBOSE] Running: whois {ip}", file=sys.stderr)
    hosting = get_hosting_info(ip)
    if hosting:
        result['hosting'] = hosting
        result['is_cdn'] = is_cdn(hosting)
        
    return result


def print_single_report(data: Dict):
    """Print the human-readable report for a single domain."""
    print(f"Looking up: {data['hostname']}")
    print(f"Root Domain: {data['root_domain']}")

    if data['redirect_target']:
        print(f"Note: This domain redirects to {data['redirect_target']}")

    if data['error']:
        print(f"Error: {data['error']}")
        return

    print(f"IP Address: {data['ip']}")

    if data['nameserver']:
        print(f"Nameserver: {data['nameserver']}")
    else:
        print("Nameserver: Unable to determine")

    if data['registrar']:
        print(f"Registrar: {data['registrar']}")
    else:
        print("Registrar: Unable to determine from WHOIS data")

    if data['hosting']:
        if data['is_cdn']:
            print(f"Hosting: {data['hosting']} (CDN)")
        else:
            print(f"Hosting: {data['hosting']}")
    else:
        print("Hosting: Unable to determine from WHOIS data")


def main():
    parser = argparse.ArgumentParser(description='Domain Hosting Lookup Tool')
    parser.add_argument('domains', nargs='*', help='Domain(s) to look up')
    parser.add_argument('--input', '-i', help='Input file with list of domains (one per line)')
    parser.add_argument('--output', '-o', help='Output CSV file (default: stdout for multiple domains)')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of concurrent threads for bulk lookup')
    parser.add_argument('--json', '-j', action='store_true', help='Output in JSON format')
    parser.add_argument('--check-redirects', action='store_true', help='Check for HTTP redirects (adds latency)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds for network operations (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output with commands being executed')

    args = parser.parse_args()

    # Check for dependencies
    try:
        subprocess.run(['whois', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("Error: 'whois' command not found. Install it with: brew install whois", file=sys.stderr)
        sys.exit(1)

    # Collect domains
    all_domains = []
    
    # 1. From arguments
    if args.domains:
        all_domains.extend(args.domains)
        
    # 2. From input file
    if args.input:
        try:
            with open(args.input, 'r') as f:
                all_domains.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
            sys.exit(1)
            
    # 3. From stdin
    if not sys.stdin.isatty():
        all_domains.extend([line.strip() for line in sys.stdin if line.strip()])

    # Deduplicate while preserving order
    all_domains = list(dict.fromkeys(all_domains))

    if not all_domains:
        parser.print_help()
        sys.exit(1)

    # Single Mode: 1 domain AND no output file specified AND not JSON mode
    if len(all_domains) == 1 and not args.output and not args.json:
        # Validate single domain strictly (exit on error)
        cleaned = clean_domain(all_domains[0])
        if not is_valid_domain(cleaned):
            print(f"Error: '{all_domains[0]}' is not a valid domain name.", file=sys.stderr)
            print("Usage: domaininfo.py <domain>", file=sys.stderr)
            print("Example: domaininfo.py example.com", file=sys.stderr)
            sys.exit(1)
        
        data = analyze_domain(
            all_domains[0],
            check_redirects=args.check_redirects,
            timeout=args.timeout,
            verbose=args.verbose
        )
        print_single_report(data)
        sys.exit(0)

    # Bulk Mode (or JSON mode)
    # If we are here, we have > 1 domain OR an output file was specified OR JSON mode
    
    fieldnames = ['hostname', 'root_domain', 'redirect_target', 'ip', 'nameserver', 'registrar', 'hosting', 'is_cdn', 'error']
    
    # Show progress if outputting to file OR if piping to stdout (not a tty)
    show_progress = args.output is not None or not sys.stdout.isatty()
    
    if show_progress and args.verbose:
        print(f"Processing {len(all_domains)} domains with {args.threads} threads...", file=sys.stderr)

    # Process all domains
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {
            executor.submit(
                analyze_domain,
                domain,
                check_redirects=args.check_redirects,
                timeout=args.timeout,
                verbose=args.verbose
            ): domain for domain in all_domains
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            data = future.result()
            results.append(data)
            
            completed += 1
            if show_progress:
                print(f"\rProgress: {completed}/{len(all_domains)}", end="", file=sys.stderr, flush=True)
    
    if show_progress:
        print("", file=sys.stderr)  # New line after progress
    
    # Output results
    if args.json:
        # JSON output
        output_data = json.dumps(results, indent=2)
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output_data)
                if show_progress:
                    print(f"Done! Report saved to {args.output}", file=sys.stderr)
            except IOError as e:
                print(f"Error writing to file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(output_data)
    else:
        # CSV output
        if args.output:
            f_out = open(args.output, 'w', newline='')
        else:
            f_out = sys.stdout

        try:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            
            for data in results:
                row = {k: v for k, v in data.items() if k in fieldnames}
                writer.writerow(row)
            
            f_out.flush()
            
            if args.output and show_progress:
                print(f"Done! Report saved to {args.output}", file=sys.stderr)

        except IOError as e:
            print(f"Error writing to CSV: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            if args.output and f_out:
                f_out.close()


if __name__ == '__main__':
    main()
