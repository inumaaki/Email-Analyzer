import hashlib
import os

class AttachmentAnalyzer:
    def __init__(self, message, sandbox_dir="./analysis/output/"):
        self.message = message
        self.sandbox_dir = sandbox_dir
        self.attachments = []

    def get_hashes(self, data: bytes) -> dict:
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return {"md5": md5, "sha1": sha1, "sha256": sha256}

    def extract_attachments(self, save_to_disk=False) -> list:
        """
        Extracts attachments from the email, profiles them, and optionally saves them.
        """
        if not self.message:
            return self.attachments
            
        for part in self.message.walk():
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                    
                size = len(payload)
                hashes = self.get_hashes(payload)
                
                # Check for double extensions
                parts = filename.split('.')
                suspicious_ext = False
                if len(parts) > 2 and parts[-1].lower() in ['exe', 'scr', 'bat', 'vbs', 'ps1', 'js']:
                    suspicious_ext = True

                attachment_info = {
                    "filename": filename,
                    "size": size,
                    "hashes": hashes,
                    "suspicious_ext": suspicious_ext,
                    "saved_path": None
                }
                
                if save_to_disk:
                    os.makedirs(self.sandbox_dir, exist_ok=True)
                    safe_filename = filename.replace("/", "_").replace("\\", "_")
                    file_path = os.path.join(self.sandbox_dir, f"{hashes['md5']}_{safe_filename}")
                    try:
                        with open(file_path, "wb") as f:
                            f.write(payload)
                        attachment_info["saved_path"] = file_path
                    except Exception as e:
                        attachment_info["saved_path"] = f"Failed to save: {e}"

                self.attachments.append(attachment_info)
                
        return self.attachments

    def run_static_analysis(self) -> dict:
        """
        Runs deep static analysis using oletools and pdfid on extracted files.
        Requires save_to_disk=True so the tools have file paths to process.
        """
        results = {}
        
        try:
            from oletools.olevba import VBA_Parser
            import subprocess
        except ImportError:
            return {"error": "Dependencies not installed. Run: pip install oletools pdfid"}

        for att in self.attachments:
            att_path = att.get("saved_path")
            filename = att.get("filename", "")
            
            anomalies = []
            
            if not att_path or not os.path.exists(att_path):
                results[filename] = {"error": "File not extracted to disk for analysis."}
                continue
                
            # --- OLETOOLS (Macros/VBA) ---
            try:
                vbaparser = VBA_Parser(att_path)
                if vbaparser.detect_vba_macros():
                    anomalies.append("[bold red]VBA Macros Detected[/bold red]")
                    results_vba = vbaparser.analyze_macros()
                    if results_vba:
                        for kw_type, keyword, description in results_vba:
                            if kw_type in ('Suspicious', 'AutoExec'):
                                anomalies.append(f"[yellow]olevba: {kw_type} ({keyword})[/yellow]")
                vbaparser.close()
            except Exception as e:
                pass # Not an OLE/Office file or parsing failed
                
            # --- PDFiD (Malicious PDF properties) ---
            if filename.lower().endswith('.pdf'):
                try:
                    # Try to use python module or subprocess as fallback
                    output = subprocess.getoutput(f"pdfid '{att_path}'")
                    for line in output.splitlines():
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0]
                            try:
                                val = int(parts[-1])
                                if key in ['/JS', '/JavaScript', '/OpenAction'] and val > 0:
                                    anomalies.append(f"[bold red]pdfid: {key} ({val})[/bold red]")
                            except ValueError:
                                pass
                except Exception as e:
                    anomalies.append(f"[dim]pdfid error: {str(e)}[/dim]")
            
            results[filename] = anomalies if anomalies else ["[green]Clean (No macros/JS)[/green]"]
            
        return results
