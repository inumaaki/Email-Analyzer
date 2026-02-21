import re
from bs4 import BeautifulSoup

class ContentAnalyzer:
    def __init__(self, bodies: dict):
        self.plain_text = bodies.get("plain", "")
        self.html_text = bodies.get("html", "")
        self.soup = BeautifulSoup(self.html_text, 'html.parser') if self.html_text else None
        
    def detect_phishing_heuristics(self) -> dict:
        """
        Looks for common phishing hallmarks in the text such as:
        - Financial urgency
        - Credential harvesting keywords
        """
        flags = []
        combined_text = (self.plain_text + " " + (self.soup.get_text() if self.soup else "")).lower()
        
        urgency_keywords = ['urgent', 'immediate action required', 'account suspended', 'verify your account', 'invoice attached', 'kindly review']
        finance_keywords = ['wire transfer', 'payment overdue', 'bank details', 'w-2', 'gift card']
        
        for kw in urgency_keywords:
            if kw in combined_text:
                flags.append(f"Urgency keyword found: '{kw}'")
                
        for kw in finance_keywords:
            if kw in combined_text:
                flags.append(f"Financial keyword found: '{kw}'")
                
        return {"flags": flags, "detected": len(flags) > 0}

    def detect_html_anomalies(self) -> dict:
        """
        Detect hidden elements and mismatched links in HTML.
        """
        anomalies = []
        if not self.soup:
            return {"anomalies": anomalies, "detected": False}
            
        # 1. Hidden text
        hidden_elements = self.soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden|opacity:\s*0', re.I))
        if len(hidden_elements) > 0:
            anomalies.append(f"Found {len(hidden_elements)} hidden HTML elements.")
            
        # 2. Mismatched Links
        # Sometimes attackers put https://paypal.com as text but href points to bad.com
        for a_tag in self.soup.find_all('a', href=True):
            href = a_tag['href']
            text = a_tag.get_text().strip()
            
            # Simple check if text looks like a URL
            if re.match(r'^(http|https)://[A-Za-z0-9\.-]+', text, re.I):
                # Basic check: is the domain the same?
                # A more thorough check is to parse the domain
                if text.lower() not in href.lower() and not href.startswith(text):
                    anomalies.append(f"Link mismatch: Display '{text}' points to '{href}'")
                    
        return {"anomalies": anomalies, "detected": len(anomalies) > 0}
