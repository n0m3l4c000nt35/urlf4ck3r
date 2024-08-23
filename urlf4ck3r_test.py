#!/usr/bin/env python3

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from pwn import *

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
    hostname = parsed_url.netloc
    path = parsed_url.path
    return scheme, hostname, path

if __name__ == "__main__":

    args, parser = get_arguments()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(1)

    all_urls = defaultdict(set)
    base_url = args.url
    visited_urls = set()
    urls_to_visit = [base_url]

    _, hostname, _ = parse_url(base_url)

    p = log.progress("")

    while urls_to_visit:
        url_to_visit = urls_to_visit.pop(0)
        visited_urls.add(url_to_visit)

        print()
        p.status(f"[{GREEN}CHECKING{END_COLOR}]: {url_to_visit}")

        response = requests.get(base_url)
        soup = BeautifulSoup(response.content, 'html.parser')

        print(f"[{GREEN}HOSTNAME{END_COLOR}]: {hostname}")
        print()

        for link in soup.find_all("a"):
            href = link.get("href")
            scheme, _, path = parse_url(href)
            test_schemes = ["http", "https"]
            if href:
                if not scheme:
                    full_url = urljoin(base_url, path)
                    all_urls["relative_urls"].add(full_url)
                elif any(scheme in href for scheme in test_schemes):
                    all_urls["absolute_urls"].add(href)

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
