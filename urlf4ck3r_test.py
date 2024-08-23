#!/usr/bin/env python3

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from pwn import *
import pdb

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GRAY = "\033[90m"
PURPLE = "\033[95m"
END_COLOR = "\033[0m"

def get_arguments():
    parser = argparse.ArgumentParser(prog="urlf4ck3r", description="Extraer las URL's del código fuente de una web", epilog="Creado por https://github.com/n0m3l4c000nt35")
    parser.add_argument("-u", "--url", type=str, dest="url", help="URL a escanear")
    return parser.parse_args(), parser

def parse_url(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    domain = parsed_url.netloc
    path = parsed_url.path
    return scheme, domain, path

def is_internal_url(base_url, url):
    base_domain = urlparse(base_url).netloc
    url_domain = urlparse(url).netloc
    return base_domain in url_domain

if __name__ == "__main__":

    args, parser = get_arguments()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(1)

    all_urls = defaultdict(set)
    base_url = args.url
    visited_urls = set()
    urls_to_visit = [base_url]

    _, domain, _ = parse_url(base_url)

    p = log.progress("")
    print()
    print(f"[{GREEN}DOMINIO{END_COLOR}]: {domain}")
    print()

    while urls_to_visit:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue
        visited_urls.add(url)

        p.status(f"[{GREEN}CHECKING{END_COLOR}]: {url}")

        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        for link in soup.find_all("a"):
            href = link.get("href")
            scheme, _, path = parse_url(href)
            test_schemes = ["http", "https"]
            if href:
                if not scheme:
                    full_url = urljoin(base_url, path)
                    all_urls["relative_urls"].add(full_url)
                    if full_url not in visited_urls:
                        urls_to_visit.append(full_url)
                elif any(scheme in href for scheme in test_schemes):
                    all_urls["absolute_urls"].add(href)
                    if is_internal_url(base_url, href) and href not in visited_urls:
                        urls_to_visit.append(href)

    print(f"[{GREEN}ABSOLUTE URLS{END_COLOR}]:")
    if len(all_urls["absolute_urls"]) == 0:
        print(f"[{RED}!{END_COLOR}] No se encontraron URL absolutas")
    else:
        for url in sorted(all_urls["absolute_urls"]):
            print(url)
    
    print()

    print(f"[{GREEN}RELATIVE URLS{END_COLOR}]:")
    if len(all_urls["absolute_urls"]) == 0:
        print(f"[{RED}!{END_COLOR}] No se encontraron URL relativas")
    else:
        for url in sorted(all_urls["relative_urls"]):
            print(url)

    print()

    print(f"[{GREEN}VISITED URLS{END_COLOR}]:")
    for url in sorted(visited_urls):
        print(url)

    print()

    print(f"[{GREEN}URLS TO VISIT{END_COLOR}]:")
    for url in sorted(urls_to_visit):
        print(url)
