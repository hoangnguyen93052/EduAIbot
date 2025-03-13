import os
import json
import requests
import threading
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'vulnerabilities': []
        }
        self.lock = threading.Lock()

    def scan(self):
        print(f'Starting scan for {self.target}')
        self.check_http_methods()
        self.check_open_ports()
        self.check_ssl_certificate()
        self.check_for_xss()
        print(f'Finished scan for {self.target}')

    def check_http_methods(self):
        url = f"{self.target}/"
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        
        for method in methods:
            response = requests.request(method, url)
            if response.status_code != 405:  # Method not allowed
                self._add_vulnerability(f'HTTP method {method} is allowed.')

    def check_open_ports(self):
        open_ports = []
        for port in range(1, 1024):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        if open_ports:
            self._add_vulnerability(f'Open ports found: {", ".join(map(str, open_ports))}')

    def check_ssl_certificate(self):
        parsed_url = urlparse(self.target)
        if parsed_url.scheme == "https":
            response = requests.get(self.target, verify=False)
            if response.ok:
                self._add_vulnerability('SSL Certificate is valid.')
            else:
                self._add_vulnerability('SSL Certificate error.')

    def check_for_xss(self):
        payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
        for payload in payloads:
            response = requests.get(self.target + '?search=' + payload)
            if payload in response.text:
                self._add_vulnerability(f'XSS vulnerability found with payload: {payload}')

    def _add_vulnerability(self, message):
        with self.lock:
            self.results['vulnerabilities'].append(message)

    def save_results(self, filename='results.json'):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)

class SecurityAnalysis:
    def __init__(self, targets):
        self.targets = targets

    def run_analysis(self):
        threads = []
        for target in self.targets:
            scanner = VulnerabilityScanner(target)
            thread = threading.Thread(target=scanner.scan)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def save_results(self, scanner, filename):
        scanner.save_results(filename)

if __name__ == "__main__":
    target_list = ['http://example.com', 'http://testsite.com']
    analysis = SecurityAnalysis(target_list)
    analysis.run_analysis()