class RiskScorer:
    def __init__(self, auth_results: dict, heuristics: dict, html_anomalies: dict, attachments: list, domains: dict):
        self.auth_results = auth_results
        self.heuristics = heuristics
        self.html_anomalies = html_anomalies
        self.attachments = attachments
        self.domains = domains
        self.score = 0
        self.breakdown = []

    def calculate_score(self) -> dict:
        """
        Calculates a risk score based on collected indicators.
        Returns a dict with the total score, risk level, and a text breakdown.
        """
        self.score = 0
        self.breakdown = []

        # 1. Authentication Check (SPF/DKIM/DMARC)
        if self.auth_results.get("spf") == "fail":
            self.score += 20
            self.breakdown.append("SPF Validation Failed (+20)")
        if self.auth_results.get("dkim") == "fail":
            self.score += 20
            self.breakdown.append("DKIM Validation Failed (+20)")
            
        # Domain Mismatches (From vs Reply-To)
        from_domain = self.domains.get("From")
        reply_to = self.domains.get("Reply-To")
        if from_domain and reply_to and from_domain != reply_to:
            self.score += 25
            self.breakdown.append(f"Domain Mismatch (From: {from_domain} vs Reply-To: {reply_to}) (+25)")

        # 2. Phishing Content Heuristics
        if self.heuristics["detected"]:
            # Up to +30 max for keywords
            pts = min(len(self.heuristics["flags"]) * 10, 30)
            self.score += pts
            self.breakdown.append(f"Suspicious Phishing Keywords Detected (+{pts})")

        # 3. HTML Anomalies
        if self.html_anomalies["detected"]:
            self.score += 15
            self.breakdown.append("HTML Anomalies Found (hidden text/mismatched links) (+15)")

        # 4. Attachments
        suspicious_attachments = 0
        for att in self.attachments:
            if att["suspicious_ext"]:
                suspicious_attachments += 1
                
        if suspicious_attachments > 0:
            self.score += 40
            self.breakdown.append("Suspicious executable/double-extension attachment found (+40)")
        elif len(self.attachments) > 0:
            self.score += 10
            self.breakdown.append("Contains generic attachments (+10)")

        # Validate Score Bounds
        self.score = max(0, min(self.score, 100))
        
        # Risk Tier
        if self.score <= 20:
            tier = "Low"
            color = "green"
        elif self.score <= 50:
            tier = "Medium"
            color = "yellow"
        elif self.score <= 80:
            tier = "High"
            color = "dark_orange"
        else:
            tier = "Critical"
            color = "red"
            
        return {
            "score": self.score,
            "tier": tier,
            "color": color,
            "breakdown": self.breakdown
        }
