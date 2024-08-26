import requests
import argparse
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
import concurrent.futures
import time
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
    )
}

def search_engine_query(query, engine_url):
    """Performs a search on a given search engine and returns a list of URLs."""
    try:
        logging.info(f"Querying {engine_url.format(query)}")
        response = requests.get(engine_url.format(query), headers=HEADERS, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return [a['href'] for a in soup.find_all('a', href=True) if query in a['href']]
    except requests.RequestException as e:
        logging.error(f"Request error with {engine_url}: {e}")
    except Exception as e:
        logging.error(f"Error querying {engine_url}: {e}")
    return []

def extract_subdomains(urls, domain):
    """Extracts subdomains from a list of URLs."""
    subdomains = set()
    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname and hostname.endswith(domain):
            subdomain = hostname.replace(domain, "").strip(".")
            if subdomain:
                subdomains.add(subdomain)
    return subdomains

def validate_subdomains(subdomains, domain):
    """Validates subdomains by performing DNS resolution."""
    valid_subdomains = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(dns_lookup, subdomain, domain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(futures):
            fqdn = futures[future]
            try:
                resolved_subdomain = future.result()
                if resolved_subdomain:
                    valid_subdomains.append(resolved_subdomain)
                    logging.info(f"Valid subdomain found: {resolved_subdomain}")
            except Exception as e:
                logging.error(f"Error resolving {fqdn}: {e}")
    return valid_subdomains

def dns_lookup(subdomain, domain):
    """Performs DNS resolution for a given subdomain."""
    fqdn = f"{subdomain}.{domain}"
    try:
        dns.resolver.resolve(fqdn, 'A')
        return fqdn
    except dns.resolver.NXDOMAIN:
        logging.debug(f"NXDOMAIN for {fqdn}")
    except dns.resolver.NoAnswer:
        logging.debug(f"No answer for {fqdn}")
    except dns.resolver.Timeout:
        logging.debug(f"Timeout while resolving {fqdn}")
    except Exception as e:
        logging.error(f"DNS resolution error for {fqdn}: {e}")
    return None

def enumerate_subdomains(domain, search_engines):
    """Performs subdomain enumeration using various search engines."""
    logging.info(f"Starting subdomain enumeration for {domain}")
    all_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(search_engine_query, domain, engine) for engine in search_engines]
        for future in concurrent.futures.as_completed(futures):
            urls = future.result()
            if urls:
                all_urls.extend(urls)
    subdomains = extract_subdomains(all_urls, domain)
    valid_subdomains = validate_subdomains(subdomains, domain)
    return valid_subdomains

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SubSniper - Professional Subdomain Enumerator')
    parser.add_argument('domain', type=str, help='Target domain to enumerate subdomains')
    parser.add_argument('-o', '--output', type=str, help='Save discovered subdomains to a file (json, csv, txt)')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='txt', help='Output format (default: txt)')
    args = parser.parse_args()

    domain = args.domain

    # List of search engine URLs to query
    search_engines = [
        "https://www.google.com/search?q=site:{}",
        "https://www.bing.com/search?q=site:{}",
        "https://search.yahoo.com/search?p=site:{}",
        # Add more engines or APIs here
    ]

    # Perform enumeration
    start_time = time.time()
    subdomains = enumerate_subdomains(domain, search_engines)
    end_time = time.time()

    if subdomains:
        logging.info(f"Subdomain enumeration completed in {end_time - start_time:.2f} seconds. Discovered subdomains:")
        for subdomain in subdomains:
            print(subdomain)

        # Save to a file if the output option is provided
        if args.output:
            if args.format == 'json':
                with open(args.output, 'w') as file:
                    json.dump(subdomains, file, indent=4)
            elif args.format == 'csv':
                with open(args.output, 'w') as file:
                    file.write("Subdomain\n")
                    for subdomain in subdomains:
                        file.write(f"{subdomain}\n")
            else:  # txt format
                with open(args.output, 'w') as file:
                    for subdomain in subdomains:
                        file.write(f"{subdomain}\n")
            logging.info(f"Subdomains saved to {args.output}")
    else:
        logging.info("No subdomains discovered.")
