#!/usr/bin/env python3

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict

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

    _, hostname, _ = parse_url(base_url)

    response = requests.get(base_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    print(f"Hostname: {hostname}")
    print()

    absolute_urls = set()
    relative_urls = set()

    for link in soup.find_all("a"):
        href = link.get("href")
        scheme, _, path = parse_url(href)
        test_schemes = ["http", "https"]
        if href:
            if not scheme:
                full_url = urljoin(base_url, path)
                relative_urls.add(full_url)
                print(f"[RELATIVA] {path} -- {full_url}")
            elif any(scheme in href for scheme in test_schemes):
                absolute_urls.add(href)
                print(f"[ABSOLUTA] {href}")

    print("[ABSOLUTE URLS]:")
    for url in absolute_urls:
        print(f"[+] {url}")

    print("[RELATIVE URLS]:")
    for url in relative_urls:
        print(f"[+] {url}")
