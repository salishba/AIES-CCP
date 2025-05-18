import os
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
from zap_scanner import ZAPScanner
from AI_Module import AIModel
from report_generator import generate_report

# Suppress TensorFlow warnings
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Based Vulnerability Scanner")
        self.root.geometry("420x180")
        self.root.resizable(False, False)

        ttk.Label(root, text="Enter Website URL:", font=("Arial", 10)).pack(pady=(20, 5))

        self.url_entry = ttk.Entry(root, width=50)
        self.url_entry.pack(pady=(0, 10))

        self.scan_btn = ttk.Button(root, text="Generate Report", command=self.start_scan)
        self.scan_btn.pack()

        self.ai = AIModel()
        if not os.path.exists("vulnerabilities.xlsx"):
            messagebox.showerror("Missing File", "vulnerabilities.xlsx not found. Please ensure it exists.")
            root.destroy()
        else:
            self.ai.train("vulnerabilities.xlsx")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (starting with http or https).")
            return

        self.scan_btn.config(text="Scanning...", state=tk.DISABLED)
        self.root.after(100, lambda: self.run_scan(url))

    def run_scan(self, url):
        try:
            scanner = ZAPScanner()
            alerts = scanner.scan(url)

            if not alerts:
                messagebox.showinfo("Scan Complete", "No vulnerabilities detected.")
                self.scan_btn.config(text="Generate Report", state=tk.NORMAL)
                return

            processed_alerts = []
            for alert in alerts:
                predicted = self.ai.predict(
                    alert.get('name', ''),
                    alert.get('description', ''),
                    alert.get('risk', 'Medium')
                )
                processed_alerts.append(predicted)

            report_path = generate_report(processed_alerts, url)

            if os.path.exists(report_path):
                webbrowser.open(report_path)
                messagebox.showinfo("Report Generated", f"Report saved and opened:\n{report_path}")

        except Exception as e:
            messagebox.showerror("Scan Error", str(e))

        finally:
            self.scan_btn.config(text="Generate Report", state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
