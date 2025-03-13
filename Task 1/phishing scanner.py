import requests
import validators
import tldextract
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('phishing-scanner')

class PhishingScanner:
    """Main application class for scanning URLs for phishing indicators."""
    
    # API key for Google Safe Browsing API - should be moved to environment variables in production
    API_KEY = "AIzaSyArwPgVli7kOg9m7hddcB1Yd3g3wtr6M7w"
    
    def __init__(self, root):
        """Initialize the application UI and components."""
        self.root = root
        self.root.title("Phishing Link Scanner")
        self.root.geometry("550x350")
        self.root.configure(bg="#1E1E2E")  # Dark background for contrast
        
        # Define vibrant color palette
        self.colors = {
            'background': '#1E1E2E',
            'primary': '#F28C28',      # Vibrant orange
            'secondary': '#7B68EE',    # Medium slate blue
            'accent': '#00FFFF',       # Cyan
            'text': '#FFFFFF',         # White
            'success': '#00FF7F',      # Spring green
            'warning': '#FFD700',      # Gold
            'error': '#FF1493',        # Deep pink
            'button': '#FF4500',       # Orange red
            'highlight': '#8A2BE2'     # Blue violet
        }
        
        # Track if scan is running
        self.scanning = False
        
        self._create_widgets()
        self._setup_layout()
    
    def _create_widgets(self):
        """Create all UI widgets."""
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles with vibrant colors
        self.style.configure('TButton', 
                             font=('Segoe UI', 11, 'bold'), 
                             background=self.colors['button'], 
                             foreground=self.colors['text'])
        
        self.style.configure('TFrame', background=self.colors['background'])
        self.style.configure('TLabel', 
                             font=('Segoe UI', 11), 
                             background=self.colors['background'], 
                             foreground=self.colors['text'])
        
        self.style.configure('Header.TLabel', 
                             font=('Segoe UI', 16, 'bold'), 
                             background=self.colors['background'], 
                             foreground=self.colors['accent'])
        
        self.style.configure('Status.TLabel', 
                             font=('Segoe UI', 9), 
                             background=self.colors['background'], 
                             foreground=self.colors['secondary'])
        
        self.style.configure('TEntry', 
                             font=('Segoe UI', 11), 
                             fieldbackground='#2A2A3E', 
                             foreground=self.colors['text'])
        
        self.style.configure('TProgressbar', 
                             background=self.colors['primary'], 
                             troughcolor='#2A2A3E')
        
        # Title Label
        self.title_label = ttk.Label(
            self.root, 
            text="Phishing Link Scanner", 
            style='Header.TLabel'
        )
        
        # Frame for URL entry and scan button
        self.input_frame = ttk.Frame(self.root, padding=10, style='TFrame')
        
        # URL Entry with label
        self.url_label = ttk.Label(
            self.input_frame, 
            text="Enter URL to scan:",
            style='TLabel'
        )
        
        self.url_entry = ttk.Entry(self.input_frame, width=50, style='TEntry')
        self.url_entry.bind("<Return>", lambda e: self.start_scan())
        
        # Create a custom button (ttk styles have limitations with colors)
        self.scan_button = tk.Button(
            self.input_frame,
            text="Scan URL",
            command=self.start_scan,
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['button'],
            fg=self.colors['text'],
            activebackground=self.colors['highlight'],
            activeforeground=self.colors['text'],
            relief=tk.RAISED,
            bd=0,
            padx=10,
            pady=5,
            cursor="hand2"
        )
        
        # Progress indicator
        self.progress = ttk.Progressbar(self.root, mode='indeterminate', style='TProgressbar')
        
        # Results Frame
        self.results_frame = ttk.Frame(self.root, padding=10, style='TFrame')
        
        # Result Label
        self.result_var = tk.StringVar()
        self.result_var.set("Enter a URL above and click 'Scan'")
        
        self.result_label = tk.Label(
            self.results_frame,
            textvariable=self.result_var,
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['background'],
            fg=self.colors['text']
        )
        
        # Status Label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            self.root,
            textvariable=self.status_var,
            style='Status.TLabel'
        )
    
    def _setup_layout(self):
        """Set up the layout using grid/pack."""
        # Main layout
        self.title_label.pack(pady=(20, 10))
        
        # Input frame
        self.input_frame.pack(fill='x', padx=20, pady=10)
        self.url_label.grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.url_entry.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
        self.scan_button.grid(row=1, column=1, sticky='e', padx=5, pady=5)
        
        # Progress bar
        self.progress.pack(fill='x', padx=20, pady=10)
        self.progress.pack_forget()  # Hide initially
        
        # Results section
        self.results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        self.result_label.pack(pady=10)
        
        # Status bar
        self.status_label.pack(side='bottom', fill='x', padx=10, pady=5)
        self.status_var.set("Ready")
    
    def start_scan(self):
        """Start the URL scanning process in a separate thread to keep UI responsive."""
        if self.scanning:
            return
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showinfo("Info", "Please enter a URL to scan.")
            return
        
        if not validators.url(url):
            messagebox.showerror("Error", "Invalid URL format. Please enter a valid URL.")
            return
        
        # Show scanning progress
        self.scanning = True
        self.progress.pack(fill='x', padx=20, pady=10)
        self.progress.start(10)
        self.result_var.set("Scanning URL... Please wait.")
        self.status_var.set(f"Scanning: {url}")
        self.scan_button.configure(state='disabled')
        
        # Run scan in background thread
        scan_thread = threading.Thread(target=self._run_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def _run_scan(self, url):
        """Run all scan checks on the URL."""
        try:
            # First check Google Safe Browsing
            logger.info(f"Checking URL against Google Safe Browsing: {url}")
            is_flagged = self._check_google_safe_browsing(url)
            
            if is_flagged:
                self._update_result("⚠️ WARNING: This URL is flagged as dangerous by Google Safe Browsing!", self.colors['error'])
                return
            
            # Run heuristic analysis
            logger.info(f"Running heuristic analysis on: {url}")
            is_suspicious = self._analyze_url_patterns(url)
            
            if is_suspicious:
                self._update_result("⚠️ Suspicious: This URL contains potential phishing characteristics.", self.colors['warning'])
                return
            
            # URL seems safe
            self._update_result("✅ Safe: No phishing indicators detected in this URL.", self.colors['success'])
        
        except Exception as e:
            logger.error(f"Error scanning URL: {str(e)}")
            self._update_result(f"Error scanning URL: {str(e)}", self.colors['error'])
        
        finally:
            # Clean up UI when done
            self.root.after(0, self._finish_scan)
    
    def _update_result(self, message, color):
        """Update result text and color in the UI thread."""
        def update():
            self.result_var.set(message)
            self.result_label.configure(fg=color)
        
        self.root.after(0, update)
    
    def _finish_scan(self):
        """Reset UI after scan completes."""
        self.progress.stop()
        self.progress.pack_forget()
        self.scan_button.configure(state='normal')
        self.scanning = False
        self.status_var.set("Scan complete")
    
    def _check_google_safe_browsing(self, url):
        """Check if URL is flagged by Google Safe Browsing API.
        
        Returns:
            bool: True if URL is flagged as dangerous, False otherwise
        """
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.API_KEY}"
            
            payload = {
                "client": {
                    "clientId": "phishing-detector-tool",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            return "matches" in result and len(result["matches"]) > 0
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            raise Exception(f"Safe Browsing API request failed: {str(e)}")
    
    def _analyze_url_patterns(self, url):
        """Analyze URL for common phishing patterns and characteristics.
        
        Returns:
            bool: True if URL has suspicious patterns, False otherwise
        """
        url_lower = url.lower()
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            # Common phishing keywords
            {"type": "keywords", "patterns": [
                "login", "verify", "secure", "account", "billing", "password", 
                "confirm", "update", "auth", "authenticate", "wallet",
                "recover", "unlock", "alert", "suspended", "unusual", "verify-now"
            ]},
            
            # Domain specific patterns
            {"type": "domain", "patterns": [
                # Domains with numbers (e.g. paypa1.com)
                r"\d+",
                # Very long subdomains
                r"^[^.]{20,}\."
            ]}
        ]
        
        # Check for keywords in URL
        for keyword in suspicious_patterns[0]["patterns"]:
            if keyword in url_lower:
                logger.info(f"Found suspicious keyword: {keyword}")
                return True
        
        # Check for common brands in suspicious domains
        common_brands = ["paypal", "apple", "microsoft", "google", "facebook", 
                         "amazon", "netflix", "instagram", "bank", "wellsfargo", 
                         "chase", "citibank", "coinbase"]
        
        for brand in common_brands:
            if brand in extracted.domain.lower():
                # Brand name in domain but not the official TLD
                if brand == "paypal" and extracted.suffix != "com":
                    logger.info(f"Brand spoofing detected: {brand} in {domain}")
                    return True
                # Look for typosquatting - small variations of brand names
                if brand not in ["bank"] and brand not in extracted.domain.lower():
                    if self._levenshtein_distance(brand, extracted.domain.lower()) <= 2:
                        logger.info(f"Possible typosquatting: {extracted.domain} similar to {brand}")
                        return True
        
        return False
    
    @staticmethod
    def _levenshtein_distance(s1, s2):
        """Calculate the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return PhishingScanner._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


def main():
    """Application entry point."""
    try:
        # Set up root window with error handling
        root = tk.Tk()
        root.protocol("WM_DELETE_WINDOW", root.quit)
        
        # Create application instance
        app = PhishingScanner(root)
        
        # Start the application
        logger.info("Starting Phishing Scanner application")
        root.mainloop()
    
    except Exception as e:
        # Handle unexpected errors
        logger.critical(f"Unhandled exception: {str(e)}", exc_info=True)
        messagebox.showerror("Critical Error", f"An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    main()