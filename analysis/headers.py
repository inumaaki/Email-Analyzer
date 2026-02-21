import re
from email.message import EmailMessage

class HeaderAnalyzer:
    def __init__(self, message: EmailMessage):
        self.message = message
        self.ips = []
        self.domains = []

    def extract_routing_ips(self) -> list:
        """
        Extract IPs from Received headers.
        """
        ips = []
        received_headers = self.message.get_all("Received", [])
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for header in received_headers:
            matches = ip_pattern.findall(header)
            ips.extend(matches)
        
        # Deduplicate while preserving relative order (mostly)
        self.ips = []
        for ip in ips:
            if ip not in self.ips:
                self.ips.append(ip)
        return self.ips

    def check_authentication(self) -> dict:
        """
        Checks Authentication-Results for SPF, DKIM, DMARC statuses.
        """
        auth_results = self.message.get_all("Authentication-Results", [])
        
        # Sometimes auth is also in SPF or DKIM specific headers
        auth_status = {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "raw": auth_results
        }
        
        for result in auth_results:
            result_lower = result.lower()
            if "spf=pass" in result_lower:
                auth_status["spf"] = "pass"
            elif "spf=fail" in result_lower or "spf=softfail" in result_lower:
                auth_status["spf"] = "fail"
                
            if "dkim=pass" in result_lower:
                auth_status["dkim"] = "pass"
            elif "dkim=fail" in result_lower:
                auth_status["dkim"] = "fail"
                
            if "dmarc=pass" in result_lower:
                auth_status["dmarc"] = "pass"
            elif "dmarc=fail" in result_lower:
                auth_status["dmarc"] = "fail"
                
        # Look for Received-SPF header
        received_spf = self.message.get_all("Received-SPF", [])
        for result in received_spf:
            result_lower = result.lower()
            if "pass" in result_lower and auth_status["spf"] == "unknown":
                auth_status["spf"] = "pass"
            elif ("fail" in result_lower or "softfail" in result_lower) and auth_status["spf"] == "unknown":
                auth_status["spf"] = "fail"

        return auth_status

    def extract_domains(self) -> dict:
        """
        Extracts domains from From, Reply-To, Return-Path.
        """
        domain_fields = ['From', 'Reply-To', 'Return-Path']
        extracted = {}
        email_pattern = re.compile(r'[\w\.-]+@([\w\.-]+)')
        
        for field in domain_fields:
            value = self.message.get(field, "")
            if value:
                match = email_pattern.search(value)
                if match:
                    extracted[field] = match.group(1)
                    if match.group(1) not in self.domains:
                        self.domains.append(match.group(1))
                else:
                    extracted[field] = None
            else:
                extracted[field] = None
                
        return extracted

    def check_spoofing(self) -> dict:
        """
        Explicitly checks if the Reply-To domain differs from the From domain.
        """
        domains = self.extract_domains()
        from_dom = domains.get("From")
        reply_to_dom = domains.get("Reply-To")
        
        is_spoofed = False
        if from_dom and reply_to_dom and from_dom.lower() != reply_to_dom.lower():
            is_spoofed = True
            
        return {
            "is_spoofed": is_spoofed,
            "from": from_dom,
            "reply_to": reply_to_dom
        }
