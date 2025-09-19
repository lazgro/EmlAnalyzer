import email
from email import policy
from email.parser import BytesParser
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import hashlib
import re
import dns.resolver
import base64

# VirusTotal API key here
VT_API_KEY =  "..................."# Replace with your actual key

class EMLAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced EML Analyzer")
        self.geometry("900x700")

        self.filename = None
        self.eml_msg = None

        # Summary data
        self.malicious_urls = 0
        self.suspicious_urls = 0
        self.malicious_files = 0
        self.suspicious_files = 0
        self.header_warnings = []

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Load EML File", command=self.load_eml).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Analyze", command=self.analyze_eml).pack(side=tk.LEFT, padx=5)

        # Output text box
        self.output = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 11))
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def load_eml(self):
        self.filename = filedialog.askopenfilename(filetypes=[("EML files", "*.eml")])
        if not self.filename:
            return
        try:
            with open(self.filename, "rb") as f:
                self.eml_msg = BytesParser(policy=policy.default).parse(f)
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, f"Loaded EML file: {self.filename}\n\n")
            self.output.insert(tk.END, f"Subject: {self.eml_msg['subject']}\n")
            self.output.insert(tk.END, f"From: {self.eml_msg['from']}\n")
            self.output.insert(tk.END, f"To: {self.eml_msg['to']}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load EML: {e}")

    def analyze_eml(self):
        if not self.eml_msg:
            messagebox.showwarning("Warning", "Please load an EML file first.")
            return

        # Reset summary counts and warnings
        self.malicious_urls = 0
        self.suspicious_urls = 0
        self.malicious_files = 0
        self.suspicious_files = 0
        self.header_warnings = []

        self.output.insert(tk.END, "\n=== ANALYSIS START ===\n")

        # 1. Header analysis
        self.analyze_headers()

        # 2. Body and URL extraction + VT URL check
        self.analyze_body_urls()

        # 3. Attachments scan and VT file check
        self.analyze_attachments()

        # 4. SPF/DKIM/DMARC basic DNS check
        self.analyze_spf_dkim_dmarc()

        # Summary
        self.print_summary()

        self.output.insert(tk.END, "\n=== ANALYSIS COMPLETE ===\n")

    def analyze_headers(self):
        self.output.insert(tk.END, "\n-- Header Analysis --\n")
        from_header = self.eml_msg['from']
        return_path = self.eml_msg['return-path']
        received = self.eml_msg.get_all('received', [])

        self.output.insert(tk.END, f"From: {from_header}\n")
        self.output.insert(tk.END, f"Return-Path: {return_path}\n")

        # Simple anomaly detection: From vs Return-Path mismatch
        if from_header and return_path and from_header not in return_path:
            warning = "Warning: 'From' and 'Return-Path' headers do not match!"
            self.output.insert(tk.END, warning + "\n")
            self.header_warnings.append(warning)

        # Show received headers (top 3)
        self.output.insert(tk.END, f"Received headers (latest 3):\n")
        for r in received[:3]:
            self.output.insert(tk.END, f"  {r}\n")

    def analyze_body_urls(self):
        self.output.insert(tk.END, "\n-- Body URL Extraction and VirusTotal Check --\n")
        urls = set()

        # Extract all URLs from the email body (both text/plain and text/html)
        for part in self.eml_msg.walk():
            ctype = part.get_content_type()
            if ctype in ["text/plain", "text/html"]:
                try:
                    text = part.get_content()
                    found_urls = re.findall(r"https?://[^\s'\"<>]+", text)
                    urls.update(found_urls)
                except Exception:
                    continue

        if not urls:
            self.output.insert(tk.END, "No URLs found in email body.\n")
            return

        self.output.insert(tk.END, f"Found {len(urls)} unique URLs:\n")
        for url in urls:
            self.output.insert(tk.END, f"  {url}\n")
        self.output.insert(tk.END, "\nChecking URLs on VirusTotal...\n")

        for url in urls:
            vt_result = self.check_vt_url(url)
            if vt_result is None:
                self.output.insert(tk.END, f"  {url} - No data on VirusTotal\n")
            else:
                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)
                self.output.insert(tk.END, f"  {url} - Malicious: {malicious}, Suspicious: {suspicious}\n")
                if malicious > 0:
                    self.malicious_urls += 1
                if suspicious > 0:
                    self.suspicious_urls += 1

    def analyze_attachments(self):
        self.output.insert(tk.END, "\n-- Attachments Analysis and VirusTotal Check --\n")
        attachments = []

        for part in self.eml_msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                attachments.append((filename, payload))

        if not attachments:
            self.output.insert(tk.END, "No attachments found.\n")
            return

        self.output.insert(tk.END, f"Found {len(attachments)} attachment(s):\n")

        for filename, data in attachments:
            size = len(data) if data else 0
            file_hash = hashlib.sha256(data).hexdigest() if data else None
            self.output.insert(tk.END, f"  {filename} (size: {size} bytes, SHA256: {file_hash})\n")

            if file_hash:
                vt_result = self.check_vt_file(file_hash)
                if vt_result is None:
                    self.output.insert(tk.END, "    No data on VirusTotal\n")
                else:
                    malicious = vt_result.get("malicious", 0)
                    suspicious = vt_result.get("suspicious", 0)
                    self.output.insert(tk.END, f"    VirusTotal - Malicious: {malicious}, Suspicious: {suspicious}\n")
                    if malicious > 0:
                        self.malicious_files += 1
                    if suspicious > 0:
                        self.suspicious_files += 1

    def analyze_spf_dkim_dmarc(self):
        self.output.insert(tk.END, "\n-- SPF/DKIM/DMARC DNS Check --\n")
        # Extract domain from From header
        from_header = self.eml_msg['from']
        domain_match = re.search(r'@([^\s>]+)', from_header or '')
        if not domain_match:
            self.output.insert(tk.END, "Could not extract domain from From header.\n")
            return
        domain = domain_match.group(1).strip()

        self.output.insert(tk.END, f"Checking DNS records for domain: {domain}\n")

        # SPF
        try:
            spf_txt = self.get_txt_record(domain, "spf")
            self.output.insert(tk.END, f"SPF record: {spf_txt}\n")
        except Exception as e:
            self.output.insert(tk.END, f"SPF record not found or error: {e}\n")

        # DKIM
        # DKIM uses selector._domainkey.domain, but we don't have selector here (advanced)
        self.output.insert(tk.END, "DKIM record check requires selector (not implemented).\n")

        # DMARC
        try:
            dmarc_txt = self.get_txt_record(f"_dmarc.{domain}")
            self.output.insert(tk.END, f"DMARC record: {dmarc_txt}\n")
        except Exception as e:
            self.output.insert(tk.END, f"DMARC record not found or error: {e}\n")

    def get_txt_record(self, domain, spf_check=None):
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if spf_check and spf_check.lower() == "spf":
                if txt.startswith("v=spf1"):
                    return txt
            else:
                return txt
        return None

    def check_vt_url(self, url):
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            resp = requests.get(vt_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return stats
            else:
                return None
        except Exception:
            return None

    def check_vt_file(self, file_hash):
        headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        try:
            resp = requests.get(vt_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return stats
            else:
                return None
        except Exception:
            return None

    def print_summary(self):
        self.output.insert(tk.END, "\n=== SUMMARY OF MALICIOUS FINDINGS ===\n")
        if self.malicious_urls == 0 and self.suspicious_urls == 0 and \
           self.malicious_files == 0 and self.suspicious_files == 0 and \
           not self.header_warnings:
            self.output.insert(tk.END, "No malicious or suspicious findings detected.\n")
            return

        if self.malicious_urls > 0:
            self.output.insert(tk.END, f"Malicious URLs found: {self.malicious_urls}\n")
        if self.suspicious_urls > 0:
            self.output.insert(tk.END, f"Suspicious URLs found: {self.suspicious_urls}\n")
        if self.malicious_files > 0:
            self.output.insert(tk.END, f"Malicious attachments found: {self.malicious_files}\n")
        if self.suspicious_files > 0:
            self.output.insert(tk.END, f"Suspicious attachments found: {self.suspicious_files}\n")

        if self.header_warnings:
            self.output.insert(tk.END, "Header warnings:\n")
            for w in self.header_warnings:
                self.output.insert(tk.END, f"  - {w}\n")

if __name__ == "__main__":
    app = EMLAnalyzerApp()
    app.mainloop()
