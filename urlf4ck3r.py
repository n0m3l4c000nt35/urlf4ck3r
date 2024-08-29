#!/usr/bin/env python3

import argparse
import sys
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urlunparse
from collections import defaultdict
import signal
import os

class URLf4ck3r:

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    GRAY = "\033[90m"
    PURPLE = "\033[95m"
    END_COLOR = "\033[0m"

    SENSITIVE_KEYWORDS = [
        "password", "user", "username", "clave", "secret", "key", "token", 
        "private", "admin", "credential", "login", "auth", "api_key", "apikey", "administrator"
    ]

    def __init__(self):
        self.all_urls = defaultdict(set)
        self.comments_data = defaultdict(list)
        self.base_url = None
        self.urls_to_scan = []
        self.flag = self.Killer()
        self.output = None


    def banner(self):
        print("""
            
 █    ██  ██▀███   ██▓      █████▒▄████▄   ██ ▄█▀ ██▀███  
 ██  ▓██▒▓██ ▒ ██▒▓██▒    ▓██   ▒▒██▀ ▀█   ██▄█▒ ▓██ ▒ ██▒
▓██  ▒██░▓██ ░▄█ ▒▒██░    ▒████ ░▒▓█    ▄ ▓███▄░ ▓██ ░▄█ ▒
▓▓█  ░██░▒██▀▀█▄  ▒██░    ░▓█▒  ░▒▓▓▄ ▄██▒▓██ █▄ ▒██▀▀█▄  
▒▒█████▓ ░██▓ ▒██▒░██████▒░▒█░   ▒ ▓███▀ ░▒██▒ █▄░██▓ ▒██▒
░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░ ▒░▓  ░ ▒ ░   ░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▒▓ ░▒▓░
░░▒░ ░ ░   ░▒ ░ ▒░░ ░ ▒  ░ ░       ░  ▒   ░ ░▒ ▒░  ░▒ ░ ▒░
 ░░░ ░ ░   ░░   ░   ░ ░    ░ ░   ░        ░ ░░ ░   ░░   ░ 
   ░        ░         ░  ░       ░ ░      ░  ░      ░     
                                 ░                        
""")


    def run(self):
        self.banner()

        args, parser = self.get_arguments()

        if len(sys.argv[1:]) == 0:
            parser.print_help()
            sys.exit(1)

        if args.output:
            self.output = args.output

        self.base_url = args.url
        self.all_urls["scanned_urls"] = set()
        self.urls_to_scan = [self.base_url]

        scheme, domain, _ = self.parse_url(self.base_url)

        print(f"\n[{self.GREEN}DOMAIN{self.END_COLOR}] {domain}\n")

        while self.urls_to_scan and not self.flag.exit():
            url = self.urls_to_scan.pop(0)
            self.scan_url(url)

        self.show_lists()

        if self.output:
            base_name = os.path.splitext(self.output)[0]
            categories = [
                ("all_urls", "all_urls"),
                ("absolute_urls", "absolute_urls"),
                ("relative_urls", "relative_urls"),
                ("request_error", "request_errors"),
                ("subdomains", "subdomains"),
                ("javascript_files", "javascript_files")
            ]

            for category, filename in categories:
                if self.all_urls[category]:
                    self.save_category_to_file(category, f"{base_name}_{filename}.txt")
            if len(self.all_urls["comments"]) != 0:
                comments_output_file = f"{base_name}_comments.txt"
                self.save_comments_to_file(comments_output_file)

        print()

        print(f"[{self.GREEN}URLS TO SCAN{self.END_COLOR}]:")
        if self.flag.exit():
            print(f"[{self.RED}!{self.END_COLOR}] Quedaron por escanear {self.RED}{len(self.urls_to_scan)}{self.END_COLOR} URLs")
            for url in sorted(self.urls_to_scan):
                print(url)
        elif len(self.urls_to_scan) == 0:
            print(f"[{self.GREEN}+{self.END_COLOR}] Se escanearon todas las URLs posibles")
        else:
            print(f"[{self.RED}!{self.END_COLOR}] Quedaron por visitar {len(self.urls_to_scan)} URLs")
            for url in sorted(self.urls_to_scan):
                print(url)


    def get_arguments(self):
        parser = argparse.ArgumentParser(prog="urlf4ck3r", description="Extraer las URL's del código fuente de una web", epilog="Creado por https://github.com/n0m3l4c000nt35")
        parser.add_argument("-u", "--url", type=str, dest="url", help="URL a escanear")
        parser.add_argument("-o", "--output", type=str, dest="output", help="Nombre del archivo de salida")
        parser.add_argument("-t", "--threads", type=int, dest="threads", help="Hilos a utilizar")
        return parser.parse_args(), parser


    def scan_url(self, url):
        if url in self.all_urls["scanned_urls"]:
            return

        self.all_urls["scanned_urls"].add(url)

        print(f"[{self.GREEN}SCANNING{self.END_COLOR}] {url}")

        try:
            res = requests.get(url, timeout=5)
            soup = BeautifulSoup(res.content, 'html.parser')

            js_files = self.find_javascript_files(soup, url)
            self.all_urls["javascript_files"].update(js_files)

            self.extract_comments(soup, url)

            for link in soup.find_all("a"):
                href = link.get("href")
                scheme, domain, path = self.parse_url(href)
                test_schemes = ["http", "https"]
                if href:
                    if not scheme:
                        full_url = urljoin(url, path)
                        if full_url not in self.all_urls["relative_urls"]:
                            self.all_urls["relative_urls"].add(full_url)
                            if self.is_jsfile(url, res):
                                self.all_urls["javascript_files"]
                        if full_url not in self.all_urls["scanned_urls"] and full_url not in self.urls_to_scan:
                            self.urls_to_scan.append(full_url)
                    elif any(scheme in href for scheme in test_schemes):
                        if href not in self.all_urls["absolute_urls"]:
                            self.all_urls["absolute_urls"].add(href)
                            if self.is_jsfile(url, res):
                                self.all_urls["javascript_files"]
                        if self.is_internal_url(self.base_url, href) and href not in self.all_urls["scanned_urls"] and href not in self.urls_to_scan:
                            self.urls_to_scan.append(href)
                        if self.is_subdomain(self.base_url, href) and href not in self.all_urls["subdomains"]:
                            subdomain = urlunparse((scheme, domain, "", "", "", ""))
                            self.all_urls["subdomains"].add(subdomain)

        except requests.Timeout as e:
            print(f"[{self.RED}REQUEST TIMEOUT{self.END_COLOR}] {url}")
        except requests.exceptions.RequestException as e:
            print(f"{self.RED}[REQUEST ERROR]{self.END_COLOR} {url}: {e}")
            self.all_urls['request_error'].add(url)


    def find_javascript_files(self, soup, base_url):
        js_files = set()
        for script in soup.find_all('script', src=True):
            js_url = script['src']
            if not urlparse(js_url).netloc:
                js_url = urljoin(base_url, js_url)
            js_files.add(js_url)
        return js_files





    def extract_subdomain(self, url):
        netloc = urlparse(url).netloc.split(".")
        if netloc[0] == "www":
            subdomains = netloc[1:]
        else:
            subdomains = netloc
        return ".".join(subdomains)


    def is_subdomain(self, base_url, url):
        base_domain = self.extract_subdomain(base_url)
        sub = self.extract_subdomain(url)
        return sub.endswith(base_domain) and sub != base_domain


    def parse_url(self, url):
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        domain = parsed_url.netloc
        path = parsed_url.path
        return scheme, domain, path


    def is_internal_url(self, base_url, url):
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain in url_domain


    def extract_comments(self, soup, url):
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = comment.strip()
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword.lower() in comment_text.lower():
                    self.comments_data[url].append(comment_text)
                    print(f"[{self.YELLOW}COMMENT FOUND{self.END_COLOR}] '{comment_text}' in {url}")
                    break


    def is_jsfile(self, url, res):
        if url.lower().endswith(('.js', '.mjs')):
            return True
        content_type = res.headers.get('Content-Type', '').lower()
        if 'javascript' in content_type:
            return True


    def save_category_to_file(self, category, file_path):
        if not self.all_urls[category]:
            return

        try:
            with open(file_path, 'w') as file:
                for url in sorted(self.all_urls[category]):
                    file.write(url + "\n")
            print(f"[{self.GREEN}CATEGORY {' '.join(category.split('_')).upper()} SAVED{self.END_COLOR}] {file_path}")
        except IOError as e:
            print(f"[{self.RED}!{self.END_COLOR}] Error al guardar el archivo {e}")


    def save_comments_to_file(self, file_path):
        try:
            with open(file_path, 'w') as file:
                for url, comments in self.comments_data.items():
                    file.write(f"URL: {url}\n")
                    for comment in comments:
                        file.write(f"  Comment: {comment}\n")
                    file.write("\n")
            print(f"[{self.GREEN}COMMENTS SAVED{self.END_COLOR}] {file_path}")
        except IOError as e:
            print(f"[{self.RED}!{self.END_COLOR}] Error al guardar el archivo {e}")


    def show_lists(self):
        list_to_show = [
            ("subdomains", "No se encontraron subdominios"),
            ("absolute_urls", "No se encontraron URL absolutas"),
            ("relative_urls", "No se encontraron URL relativas"),
            ("javascript_files", "No se encontraron archivos JavaScript"),
            ("scanned_urls", None)
        ]
        for url_list, err_msg in list_to_show:
            title = " ".join(url_list.split("_")).upper() if "_" in url_list else url_list.upper()
            print(f"\n[{self.RED}{len(self.all_urls[url_list])}{self.END_COLOR}][{self.GREEN}{title}{self.END_COLOR}]:")
            if len(self.all_urls[url_list]) == 0:
                print(f"[{self.RED}!{self.END_COLOR}] {err_msg}")
            else:
                for url in sorted(self.all_urls[url_list]):
                    print(url)
        print()


    class Killer:
        def __init__(self):
            self.state = False
            signal.signal(signal.SIGINT, self.change_state)

        def change_state(self, signum, frame):
            print(f"\n[{URLf4ck3r.RED}!{URLf4ck3r.END_COLOR}] Saliendo...")
            self.state = True

        def exit(self):
            return self.state


if __name__ == "__main__":
    urlf4ck3r = URLf4ck3r()
    urlf4ck3r.run()
