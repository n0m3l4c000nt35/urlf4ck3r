#!/usr/bin/env python3

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
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

class Killer:
    def __init__(self):
        self.state = False
        signal.signal(signal.SIGINT, self.change_state)

    def change_state(self, signum, frame):
        print()
        print(f"[{RED}!{END_COLOR}] Saliendo...")
        self.state = True

    def exit(self):
        return self.state

flag = Killer()

def get_arguments():
    parser = argparse.ArgumentParser(prog="urlf4ck3r", description="Extraer las URL's del código fuente de una web", epilog="Creado por https://github.com/n0m3l4c000nt35")
    parser.add_argument("-u", "--url", type=str, dest="url", help="URL a escanear")
    return parser.parse_args(), parser

def extract_subdomain(url):
    netloc = urlparse(url).netloc.split(".")
    if netloc[0] == "www":
        subdomains = netloc[1:]
    else:
        subdomains = netloc
    return ".".join(subdomains)

def is_subdomain(base_url, url):
    base_domain = urlparse(base_url).netloc
    return url.endswith(base_domain) and url != base_domain

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

def show_list(url_list, err_msg=None):
    print()
    title = " ".join(url_list.split("_")).upper() if "_" in url_list else url_list.upper()
    print(f"[{GREEN}{title}{END_COLOR}]:")
    if len(all_urls[url_list]) == 0:
        print(f"[{RED}!{END_COLOR}] {err_msg}")
    else:
        for url in sorted(all_urls[url_list]):
            print(url)

if __name__ == "__main__":

    args, parser = get_arguments()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(1)

    all_urls = defaultdict(set)
    base_url = args.url
    all_urls["scanned_urls"] = set()
    urls_to_visit = [base_url]

    scheme, domain, _ = parse_url(base_url)

    #p = log.progress("")
    print()
    print(f"[{GREEN}DOMAIN{END_COLOR}] {domain}")
    print()

    while urls_to_visit and not flag.exit():
        url = urls_to_visit.pop(0)
        if url in all_urls["scanned_urls"]:
            continue
        all_urls["scanned_urls"].add(url)

        #p.status(f"[{GREEN}CHECKING{END_COLOR}]: {url}")
        print(f"[{GREEN}SCANNING{END_COLOR}] {url}")

        res = requests.get(url)
        soup = BeautifulSoup(res.content, 'html.parser')

        for link in soup.find_all("a"):
            href = link.get("href")
            scheme, _, path = parse_url(href)
            test_schemes = ["http", "https"]
            if href:
                if not scheme:
                    full_url = urljoin(url, path)
                    if full_url not in all_urls["relative_urls"]:
                        all_urls["relative_urls"].add(full_url)
                    if full_url not in all_urls["scanned_urls"] and full_url not in urls_to_visit:
                        urls_to_visit.append(full_url)
                elif any(scheme in href for scheme in test_schemes):
                    if href not in all_urls["absolute_urls"]:
                        all_urls["absolute_urls"].add(href)
                    if is_internal_url(base_url, href) and href not in all_urls["scanned_urls"] and href not in urls_to_visit:
                        urls_to_visit.append(href)
                    ext = extract_subdomain(href)
                    if is_subdomain(base_url, ext) and ext not in all_urls["subdomains"]:
                        subdomain = urlunparse((scheme, ext, "", "", "", ""))
                        all_urls["subdomains"].add(subdomain)

    #exit()
    print()

    for list_name, msg in [("subdomains", "No se encontraron subdominios"),("absolute_urls", "No se encontraron URL absolutas"),("relative_urls", "No se encontraron URL relativas"),("scanned_urls", None)]:
        show_list(list_name, msg)

    print()

    print(f"[{GREEN}URLS TO SCAN{END_COLOR}]:")
    if flag.exit():
        print(f"[{RED}!{END_COLOR}] Quedaron por escanear {RED}{len(urls_to_visit)}{END_COLOR} URLs")
        for url in sorted(urls_to_visit):
            print(url)
    elif len(urls_to_visit) == 0:
        print(f"[{GREEN}+{END_COLOR}] Se escanearon todas las URLs posibles")
    else:
        print(f"[+] Quedaron por visitar {len(urls_to_visit)} URLs")
        for url in sorted(urls_to_visit):
            print(url)
