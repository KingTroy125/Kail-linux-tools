import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
from datetime import datetime
import ipaddress

class PingScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Ping Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Scan variables
        self.scanning = False
        self.scan_thread = None
        self.hosts = []
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Ping Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Target input frame
        input_frame = ttk.LabelFrame(main_frame, text="Scan Target", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Target entry
        ttk.Label(input_frame, text="IP/Range:").pack(side=tk.LEFT, padx=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(input_frame, textvariable=self.target_var, width=25)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "192.168.1.0/24")
        
        # Examples
        ttk.Label(input_frame, 
                 text="Examples: 192.168.1.1, 192.168.1.1-100, 192.168.1.0/24",
                 font=('Helvetica', 9)).pack(side=tk.LEFT, padx=5)
        
        # Scan type selection
        scan_frame = ttk.LabelFrame(main_frame, text="Scan Type", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        self.scan_type = tk.StringVar(value='sn')
        
        # Radio buttons for scan types
        ttk.Radiobutton(scan_frame, 
                        text="Standard Ping Scan (-sP)", 
                        variable=self.scan_type, 
                        value='sP').pack(anchor='w', padx=5, pady=2)
        
        ttk.Radiobutton(scan_frame, 
                        text="No Port Scan (-sn)", 
                        variable=self.scan_type, 
                        value='sn').pack(anchor='w', padx=5, pady=2)
        
        # Control frame
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.toggle_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Status label
        self.status_label = ttk.Label(control_frame, text="Ready", font=('Helvetica', 10))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Text widget for raw output
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)
    
    def validate_target(self, target_str):
        """Validate the target IP or range"""
        target_str = target_str.strip()
        if not target_str:
            messagebox.showerror("Error", "Please enter an IP address or range to scan")
            return None
        
        # Check for single IP
        try:
            ipaddress.IPv4Address(target_str)
            return target_str
        except ipaddress.AddressValueError:
            pass
        
        # Check for IP range (e.g., 192.168.1.1-100)
        if '-' in target_str:
            base_ip = target_str.split('-')[0]
            try:
                ipaddress.IPv4Address(base_ip)
                return target_str
            except ipaddress.AddressValueError:
                pass
        
        # Check for CIDR notation (e.g., 192.168.1.0/24)
        try:
            ipaddress.IPv4Network(target_str, strict=False)
            return target_str
        except ValueError:
            pass
        
        messagebox.showerror("Invalid Input", 
                           "Please enter a valid IP address or range\n"
                           "Examples:\n"
                           " - Single IP: 192.168.1.1\n"
                           " - IP Range: 192.168.1.1-100\n"
                           " - CIDR Range: 192.168.1.0/24")
        return None
    
    def toggle_scan(self):
        """Start or stop scanning"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start scanning the target"""
        target_str = self.target_var.get()
        target = self.validate_target(target_str)
        if not target:
            return
        
        self.scanning = True
        self.scan_button.config(text="Stop Scan")
        self.progress.start()
        self.status_label.config(text=f"Scanning {target}...")
        self.clear_results()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_ping_scan,
            args=(target,),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_ping_scan(self, target):
        """Run the ping scan with selected options"""
        try:
            scan_type = self.scan_type.get()
            self.append_output(f"Starting {scan_type} scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            command = ['sudo', 'nmap', f'-{scan_type}', target]
            self.append_output("Command: " + ' '.join(command) + "\n\n")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.append_output(output)
                
                if not self.scanning:
                    process.terminate()
                    break
            
            if self.scanning:  # Only process if scan wasn't stopped
                return_code = process.poll()
                if return_code == 0:
                    self.append_output(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                    self.status_label.config(text="Scan completed")
                else:
                    error = process.stderr.read()
                    self.append_output(f"\nScan failed:\n{error}\n")
                    self.status_label.config(text="Scan failed")
            
        except Exception as e:
            self.append_output(f"Unexpected error: {str(e)}\n")
            self.status_label.config(text="Scan failed")
        finally:
            if self.scanning:
                self.scanning = False
                self.scan_button.config(text="Start Scan")
                self.progress.stop()
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.scan_button.config(text="Start Scan")
        self.progress.stop()
        self.status_label.config(text="Scan stopped")
        self.append_output("\n[Scan stopped by user]\n")
    
    def clear_results(self):
        """Clear previous scan results"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def append_output(self, text):
        """Append text to output window"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.root.update()
    
    def on_closing(self):
        """Handle window closing"""
        if self.scanning:
            self.stop_scan()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
