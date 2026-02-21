import email
from email import policy
from email.message import EmailMessage

class EmailParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.message = None

    def read_email(self) -> EmailMessage:
        """
        Reads the .eml file and returns an EmailMessage object.
        Uses policy.default for modern RFC compliant parsing.
        """
        try:
            with open(self.file_path, "rb") as f:
                self.message = email.message_from_binary_file(f, policy=policy.default)
            return self.message
        except Exception as e:
            raise ValueError(f"Failed to read email file: {e}")

    def validate_format(self) -> bool:
        """
        Validates whether the loaded file is actually an email.
        """
        if not self.message:
            return False
        # A basic check: does it have typical headers like From or Date?
        if not (self.message.get("From") or self.message.get("Date") or self.message.get("Received")):
            return False
        return True

    def get_basic_headers(self) -> dict:
        """
        Extracts basic headers for quick triage.
        """
        if not self.message:
            return {}
        return {
            "Message-ID": self.message.get("Message-ID", "N/A"),
            "Date": self.message.get("Date", "N/A"),
            "From": self.message.get("From", "N/A"),
            "To": self.message.get("To", "N/A"),
            "Reply-To": self.message.get("Reply-To", "N/A"),
            "Subject": self.message.get("Subject", "N/A"),
            "Return-Path": self.message.get("Return-Path", "N/A")
        }

    def get_body(self) -> dict:
        """
        Extracts the plain text and HTML bodies from the email.
        """
        if not self.message:
            return {"plain": "", "html": ""}
            
        bodies = {"plain": "", "html": ""}
        
        # EmailMessage from policy.default has walk()
        for part in self.message.walk():
            # If it is a multipart or not text, skip it for the body extraction
            if part.get_content_maintype() == 'text':
                content_type = part.get_content_subtype()
                try:
                    payload = part.get_content()
                    if content_type == 'plain':
                        bodies["plain"] += payload + "\n"
                    elif content_type == 'html':
                        bodies["html"] += payload + "\n"
                except Exception as e:
                    pass # Ignore decoding errors for now
                    
        return bodies

    def get_hashes(self) -> dict:
        """
        Calculates MD5, SHA1, and SHA256 for the .eml file and its body content.
        """
        import hashlib
        hashes = {
            "file": {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}, 
            "content": {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}
        }
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
                hashes["file"]["md5"] = hashlib.md5(data).hexdigest()
                hashes["file"]["sha1"] = hashlib.sha1(data).hexdigest()
                hashes["file"]["sha256"] = hashlib.sha256(data).hexdigest()
                
            bodies = self.get_body()
            content = (bodies.get("plain", "") + bodies.get("html", "")).encode("utf-8", errors="ignore")
            if content:
                hashes["content"]["md5"] = hashlib.md5(content).hexdigest()
                hashes["content"]["sha1"] = hashlib.sha1(content).hexdigest()
                hashes["content"]["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            pass
        return hashes
