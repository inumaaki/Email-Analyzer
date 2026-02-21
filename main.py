import argparse
import sys
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
from rich.columns import Columns

console = Console()

def get_banner():
    # Make the banner super compact (1 line) for dashboard
    banner_text = r"Email Analyzer (EA) - Threat Hunting & Analysis"
    return Panel(
        Align.center(Text(banner_text, style="bold cyan")), 
        box=box.ROUNDED, 
        border_style="blue",
        padding=(0, 0)
    )

def main():
    parser = argparse.ArgumentParser(
        description="SOC Email Analyzer (SEA) - A tool for offline-first email analysis and threat intelligence."
    )
    
    # Core arguments
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the .eml or .msg file to analyze")
    
    # Analysis modes
    parser.add_argument("--deep", action="store_true", help="Perform deep static analysis (YARA, oletools, pdfid)")
    parser.add_argument("--extract-attachments", action="store_true", help="Extract attachments to a sandboxed folder")
    
    # Online enrichment
    parser.add_argument("--enrich", action="store_true", help="Enable online threat intelligence enrichment (VT, AbuseIPDB)")
    
    # Export options
    parser.add_argument("--export", type=str, help="Export results to a specific JSON file path")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output (useful with --export)")

    args = parser.parse_args()

    # Auto-enable enrichment if keys are present
    from core.config import VT_API_KEY, ABUSEIPDB_API_KEY
    if VT_API_KEY or ABUSEIPDB_API_KEY:
        args.enrich = True

    # Initialize and parsing logic
    try:
        from core.parser import EmailParser
        parser_obj = EmailParser(args.file)
        parser_obj.read_email()
        if not parser_obj.validate_format():
            if not args.silent: console.print("[red]Error: The provided file does not appear to be a valid email.[/red]")
            sys.exit(1)
            
        headers = parser_obj.get_basic_headers()
        file_hashes = parser_obj.get_hashes()
        
        # Renderables
        header_renderable = None
        auth_renderable = None
        content_renderable = None
        ioc_renderable = None
        att_renderable = None
        risk_renderable = None
        intel_renderable = None

        if not args.silent:
            header_table = Table(title="Basic Headers", box=box.ROUNDED, show_header=False, title_style="bold magenta", title_justify="left", expand=True)
            header_table.add_column("Key", style="cyan", justify="right")
            header_table.add_column("Value", style="white", overflow="fold")
            for k, v in headers.items():
                header_table.add_row(k, str(v) if v else "")
                
            hash_table = Table(box=box.ROUNDED, show_header=False, expand=True)
            hash_table.add_column("Type", style="dim cyan")
            hash_table.add_column("Hash", style="dim white", overflow="fold")
            hash_table.add_row("File MD5", file_hashes["file"]["md5"])
            hash_table.add_row("File SHA2", file_hashes["file"]["sha256"])
            hash_table.add_row("Body MD5", file_hashes["content"]["md5"])
            
            header_renderable = Group(header_table, hash_table)
                
        # Header Analysis
        from analysis.headers import HeaderAnalyzer
        header_analyzer = HeaderAnalyzer(parser_obj.message)
        auth = header_analyzer.check_authentication()
        ips = header_analyzer.extract_routing_ips()
        domains = header_analyzer.extract_domains()
        spoof_check = header_analyzer.check_spoofing()
        
        if not args.silent:
            auth_table = Table(title="Auth & Routing", box=box.ROUNDED, title_style="bold magenta", title_justify="left", expand=True)
            auth_table.add_column("Check/Entity", style="cyan")
            auth_table.add_column("Details", style="white")
            
            # Formatted auth statuses
            for key in ['spf', 'dkim', 'dmarc']:
                v = auth[key]
                color = "green" if v.lower() == "pass" else ("red" if v.lower() == "fail" else "yellow")
                auth_table.add_row(key.upper(), f"[{color}]{v}[/{color}]")
            
            ips_str = "\n".join(ips) if ips else "None found."
            auth_table.add_row("Routing IPs", ips_str)
            
            domain_lines = [f"{k}: {d}" for k, d in domains.items() if d]
            domains_str = "\n".join(domain_lines) if domain_lines else "None found."
            auth_table.add_row("Domains", domains_str)
            
            if spoof_check["is_spoofed"]:
                auth_table.add_row("Spoofing", "[bold red]FAIL (From != Reply-To)[/bold red]")
            else:
                auth_table.add_row("Spoofing", "[green]PASS[/green]")
                
            auth_renderable = auth_table
                    
        # Content Analysis
        from analysis.content import ContentAnalyzer
        bodies = parser_obj.get_body()
        content_analyzer = ContentAnalyzer(bodies)
        heuristics = content_analyzer.detect_phishing_heuristics()
        html_anomalies = content_analyzer.detect_html_anomalies()
        
        if not args.silent:
            content_table = Table(title="Content Analysis", box=box.ROUNDED, title_style="bold magenta", show_header=False, title_justify="left", expand=True)
            content_table.add_column("Type", style="cyan", justify="right")
            content_table.add_column("Details", style="white")
            
            if heuristics["detected"]:
                h_text = "\n".join([f"[red]✗ {flag}[/red]" for flag in heuristics["flags"]])
            else:
                h_text = "[green]✓ No phishing keywords[/green]"
            content_table.add_row("Heuristics", h_text)
            
            if html_anomalies["detected"]:
                a_text = "\n".join([f"[red]✗ {anomaly}[/red]" for anomaly in html_anomalies["anomalies"]])
            else:
                a_text = "[green]✓ No HTML anomalies[/green]" if content_analyzer.soup else "[dim]N/A (No HTML)[/dim]"
            content_table.add_row("HTML", a_text)
            content_renderable = content_table

        # URL & IOC Extraction
        from analysis.urls import URLExtractor
        combined_text = bodies["plain"] + "\n" + (content_analyzer.soup.get_text() if content_analyzer.soup else "")
        extractor = URLExtractor(combined_text)
        extractor.extract_all()
        
        if not args.silent:
            ioc_table = Table(title="Extracted IOCs", box=box.ROUNDED, title_style="bold magenta", title_justify="left", expand=True)
            ioc_table.add_column("Type", style="cyan", width=8)
            ioc_table.add_column("Value", style="yellow", overflow="fold")
            
            found_iocs = False
            if extractor.urls:
                found_iocs = True
                ioc_table.add_row("URLs", "\n".join(f"• {extractor.get_defanged_ioc(u, 'url')}" for u in extractor.urls[:2]) + (f"\n[dim]+{len(extractor.urls)-2} more[/dim]" if len(extractor.urls) > 2 else ""))
            if extractor.ips:
                found_iocs = True
                ioc_table.add_row("IPs", "\n".join(f"• {extractor.get_defanged_ioc(ip, 'ip')}" for ip in extractor.ips[:2]) + (f"\n[dim]+{len(extractor.ips)-2} more[/dim]" if len(extractor.ips) > 2 else ""))
            if extractor.emails:
                found_iocs = True
                ioc_table.add_row("Emails", "\n".join(f"• {extractor.get_defanged_ioc(e, 'email')}" for e in extractor.emails[:2]) + (f"\n[dim]+{len(extractor.emails)-2} more[/dim]" if len(extractor.emails) > 2 else ""))
                
            if found_iocs:
                ioc_renderable = ioc_table
            else:
                ioc_renderable = Panel("[green]No IOCs found.[/green]", title="Extracted IOCs", title_align="left", box=box.ROUNDED, border_style="green", expand=True)

        # Attachment Analysis
        from analysis.attachments import AttachmentAnalyzer
        from core.config import SANDBOX_DIR
        
        if args.deep:
            args.extract_attachments = True
            
        att_analyzer = AttachmentAnalyzer(parser_obj.message, sandbox_dir=SANDBOX_DIR)
        attachments = att_analyzer.extract_attachments(save_to_disk=args.extract_attachments)
        
        deep_results = {}
        if args.deep:
            deep_results = att_analyzer.run_static_analysis()
            
        if not args.silent:
            if attachments:
                att_table = Table(title="Attachments", box=box.ROUNDED, title_style="bold magenta", title_justify="left", expand=True)
                att_table.add_column("File", style="magenta", overflow="fold")
                att_table.add_column("Status", style="dim", overflow="fold")
                
                for att in attachments[:2]: # Limit for compact view
                    color = "[red]" if att["suspicious_ext"] else "[magenta]"
                    status = "[red]⚠ Suspicious Ext[/red]" if att['suspicious_ext'] else "[green]OK[/green]"
                    
                    if args.deep and att['filename'] in deep_results:
                        res = deep_results[att['filename']]
                        if isinstance(res, list):
                            status += f"\n{' | '.join(res)}"
                        elif isinstance(res, dict) and "error" in res:
                            status += f"\n[dim]{res['error']}[/dim]"
                            
                    att_table.add_row(
                        f"{color}{att['filename']}{color.replace('[', '[/')}", 
                        f"{att['size']}B | {status}"
                    )
                if len(attachments) > 2:
                     att_table.add_row("...", f"[dim]+{len(attachments)-2} more attachments[/dim]")
                
                att_renderable = att_table
            else:
                att_renderable = Panel("[green]No attachments[/green]", title="Attachments", title_align="left", box=box.ROUNDED, border_style="green", expand=True)

        # Risk Scoring
        from analysis.scoring import RiskScorer
        scorer = RiskScorer(auth, heuristics, html_anomalies, attachments, domains)
        risk = scorer.calculate_score()
        
        if not args.silent:
            risk_color = risk['color']
            
            risk_text = f"Score: [{risk_color}][bold]{risk['score']}/100[/bold][/{risk_color}] | "
            risk_text += f"Level: [{risk_color}][bold]{risk['tier'].upper()}[/bold][/{risk_color}]\n"
            if risk["breakdown"]:
                risk_text += "\n".join(f"[bold {risk_color}]>[/bold {risk_color}] {item}" for item in risk["breakdown"][:4])
                if len(risk["breakdown"]) > 4:
                    risk_text += f"\n[dim]... and {len(risk['breakdown'])-4} more[/dim]"
            else:
                risk_text += "[green]✓ No risk indicators triggered.[/green]"
                
            risk_renderable = Panel(risk_text.strip(), title="Risk Assessment", title_align="left", box=box.HEAVY, border_style=risk_color, expand=True)

        # Optional Output Export Data Compilation
        final_report = {
            "headers": headers,
            "authentication": auth,
            "routing_ips": ips,
            "domains": domains,
            "heuristics": heuristics,
            "html_anomalies": html_anomalies,
            "iocs": {
                "urls": extractor.urls,
                "ips": extractor.ips,
                "emails": extractor.emails
            },
            "attachments": attachments,
            "risk_score": risk
        }

        # Threat Intelligence (Online Enrichment)
        if args.enrich:
            from intel.online import OnlineIntel
            intel_api = OnlineIntel()
            
            if not args.silent:
                intel_table = Table(title="Live Threat Intel", box=box.ROUNDED, title_style="bold magenta", title_justify="left", expand=True)
                intel_table.add_column("Target", style="cyan")
                intel_table.add_column("Result", style="white", overflow="fold")
                
            intel_results = {"vt": [], "abuseipdb": []}
            
            # Check IPs
            all_ips = list(set(ips + extractor.ips))
            for ip in all_ips[:4]:
                if ABUSEIPDB_API_KEY:
                    result = intel_api.check_abuseipdb(ip)
                    intel_results["abuseipdb"].append({"ip": ip, "result": result})
                    if not args.silent:
                        conf = result.get('abuse_confidence', 'Error')
                        color = "red" if isinstance(conf, int) and conf > 0 else "green"
                        intel_table.add_row(ip, f"[{color}]Abuse Confidence: {conf}%[/] (AbuseIPDB)")
                    
            # Check File Hashes
            if VT_API_KEY:
                # Base file
                result = intel_api.check_vt_hash(file_hashes['file']['sha256'])
                intel_results["vt"].append({"filename": "Main .eml File", "hash": file_hashes['file']['sha256'], "result": result})
                if not args.silent:
                    if "error" in result:
                        intel_table.add_row("Main File", f"[yellow]{result['error']}[/] (VT)")
                    else:
                        mal = result['malicious']
                        color = "red" if mal > 0 else "green"
                        intel_table.add_row("Main File", f"[{color}]Malicious: {mal}[/], Suspicious: {result['suspicious']} (VT)")
                
                # Attachments
                for att in attachments[:2]:
                    h = att['hashes']['sha256']
                    result = intel_api.check_vt_hash(h)
                    intel_results["vt"].append({"filename": att['filename'], "hash": h, "result": result})
                    if not args.silent:
                        if "error" in result:
                            intel_table.add_row(att['filename'], f"[yellow]{result['error']}[/] (VT)")
                        else:
                            mal = result['malicious']
                            color = "red" if mal > 0 else "green"
                            intel_table.add_row(att['filename'], f"[{color}]Malicious: {mal}[/], Suspicious: {result['suspicious']} (VT)")
                        
            if not args.silent:
                if intel_table.row_count > 0:
                    intel_renderable = intel_table
                else:
                    intel_renderable = Panel("[dim]No valid API keys found.[/dim]", title="Live Threat Intel", title_align="left", box=box.ROUNDED, expand=True)
            final_report["intel_enrichment"] = intel_results

        # Layout Assembly for Dashboard
        if not args.silent:
            # Row 1: Headers (Span 1), Auth (Span 1), Risk (Span 1)
            row1_grid = Table.grid(expand=True, padding=(0, 1))
            row1_grid.add_column(ratio=1, max_width=60)
            row1_grid.add_column(ratio=1, max_width=60)
            row1_grid.add_column(ratio=1, max_width=60)
            row1_grid.add_row(header_renderable, auth_renderable, risk_renderable)
            
            # Row 2: Content (Span 1), IOCs (Span 1), Attachments / Intel (Span 1)
            row2_grid = Table.grid(expand=True, padding=(0, 1))
            row2_grid.add_column(ratio=1, max_width=60)
            row2_grid.add_column(ratio=1, max_width=60)
            row2_grid.add_column(ratio=1, max_width=60)
            
            right_col_renderables = [att_renderable]
            if args.enrich and intel_renderable:
                right_col_renderables.append(intel_renderable)
            right_col_group = Group(*right_col_renderables)
                
            row2_grid.add_row(content_renderable, ioc_renderable, right_col_group)
            
            main_layout = Table.grid(expand=True)
            main_layout.add_column()
            main_layout.add_row(get_banner())
            main_layout.add_row(row1_grid)
            main_layout.add_row(row2_grid)

            # --- FULL WIDTH LINKS PANEL FOR KALI TERMINAL COMPATIBILITY ---
            links_group = []
            links_group.append(f"[cyan]File MD5:[/cyan]  https://www.virustotal.com/gui/search/{file_hashes['file']['md5']}")
            links_group.append(f"[cyan]File SHA2:[/cyan] https://www.virustotal.com/gui/search/{file_hashes['file']['sha256']}")
            
            if extractor.urls:
                links_group.append(f"[cyan]URL (VT):[/cyan]   https://www.virustotal.com/gui/search/{extractor.urls[0]}")
                links_group.append(f"[cyan]URL (Scan):[/cyan] https://urlscan.io/search/#{extractor.urls[0]}")
            if extractor.ips:
                links_group.append(f"[cyan]IP (VT):[/cyan]    https://www.virustotal.com/gui/search/{extractor.ips[0]}")
            if attachments:
                for att in attachments[:2]:
                    links_group.append(f"[cyan]Att. ({att['filename']}):[/cyan] https://www.virustotal.com/gui/search/{att['hashes']['sha256']}")

            links_text = Text.from_markup("\n".join(links_group), overflow="fold")
            links_panel = Panel(links_text, title="One-Click Investigation Links", title_align="left", box=box.ROUNDED, border_style="cyan", expand=True)
            main_layout.add_row(links_panel)
            
            if args.enrich:
                console.print("[yellow]WARNING: Online enrichment enabled. External API requests made.[/yellow]")
            console.print(main_layout)

        # JSON Export
        if args.export:
            from reporting.export import export_to_json
            success, err = export_to_json(args.export, final_report)
            if success:
                if not args.silent: console.print(f"[green]Report exported to {args.export}[/green]")
            else:
                if not args.silent: console.print(f"[red]Failed to export JSON report: {err}[/red]")

    except Exception as e:
        console.print(Panel(f"Error during analysis: {e}", title="Fatal Error", style="bold red", box=box.DOUBLE))
        sys.exit(1)

if __name__ == "__main__":
    main()
