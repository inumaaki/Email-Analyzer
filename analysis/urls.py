import re
import tldextract

class URLExtractor:
    def __init__(self, text: str):
        self.text = text
        self.urls = []
        self.ips = []
        self.emails = []
        self.domains = []

    def extract_all(self):
        """
        Runs regex engine to extract URLs, IPs, and Emails.
        """
        # URLs
        url_pattern = re.compile(r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))')
        matches = url_pattern.findall(self.text)
        self.urls = list(set([match[0] for match in matches]))

        # IPv4
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = ip_pattern.findall(self.text)
        self.ips = list(set(ips))

        # Emails
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        emails = email_pattern.findall(self.text)
        self.emails = list(set(emails))
        
        # Domains from URLs
        for url in self.urls:
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            if domain and domain != ".":
                self.domains.append(domain.lower())
                
        self.domains = list(set(self.domains))
        
    def get_defanged_ioc(self, ioc: str, ioc_type: str = "url") -> str:
        """
        Defangs an IOC for safe sharing.
        """
        if ioc_type == "url":
            defanged = ioc.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
            defanged = defanged.replace(".", "[.]")
            return defanged
        elif ioc_type == "ip" or ioc_type == "domain":
            return ioc.replace(".", "[.]")
        elif ioc_type == "email":
            return ioc.replace("@", "[AT]").replace(".", "[.]")
        return ioc
