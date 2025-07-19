import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import re
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
        results_frame = ttk.LabelFrame(main_frame, text="Discovered Hosts", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for results
        self.results_tree = ttk.Treeview(results_frame, 
                                       columns=('ip', 'hostname', 'mac', 'vendor'), 
                                       show='headings')
        
        # Configure columns
        columns = [
            ('ip', 'IP Address', 150),
            ('hostname', 'Hostname', 200),
            ('mac', 'MAC Address', 150),
            ('vendor', 'Vendor', 250)
        ]
        
        for col_id, col_text, width in columns:
            self.results_tree.heading(col_id, text=col_text)
            self.results_tree.column(col_id, width=width, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        
        # Details frame
        details_frame = ttk.LabelFrame(main_frame, text="Scan Details", padding="10")
        details_frame.pack(fill=tk.BOTH, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
    
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
            self.append_details(f"Starting {scan_type} scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            command = ['sudo', 'nmap', '-oX', '-', '-n', f'-{scan_type}', target]
            self.append_details("Command: " + ' '.join(command) + "\n")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.scanning:  # Only process if scan wasn't stopped
                self.parse_ping_results(result.stdout)
                self.append_details(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                self.status_label.config(text=f"Found {len(self.hosts)} hosts")
            
        except subprocess.CalledProcessError as e:
            self.append_details(f"Error running nmap:\n{e.stderr}\n")
            self.status_label.config(text="Scan failed - try with sudo")
        except Exception as e:
            self.append_details(f"Unexpected error: {str(e)}\n")
            self.status_label.config(text="Scan failed")
        finally:
            if self.scanning:
                self.scanning = False
                self.scan_button.config(text="Start Scan")
                self.progress.stop()
    
    def parse_ping_results(self, xml_output):
        """Parse nmap ping scan results"""
        try:
            host_blocks = re.findall(r'<host .*?>.*?</host>', xml_output, re.DOTALL)
            self.append_details(f"\nFound {len(host_blocks)} active hosts\n")
            
            for host in host_blocks:
                # Get IP address
                ip = self.get_xml_field(host, r'<address addr="([^"]+)" addrtype="ipv4"/>')
                
                # Get MAC and vendor
                mac = self.get_xml_field(host, r'<address addr="([^"]+)" addrtype="mac"/>')
                vendor = self.get_xml_field(host, r'vendor="([^"]+)"')
                
                # Get hostname
                hostname = self.get_xml_field(host, r'<hostname name="([^"]+)"')
                
                # Add to results
                self.hosts.append({
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor
                })
                
                # Add to treeview
                self.results_tree.insert('', tk.END, values=(
                    ip, hostname, mac, vendor
                ))
                
                # Add to details
                self.append_details(
                    f"Host: {ip}\n"
                    f"Hostname: {hostname}\n"
                    f"MAC: {mac}\n"
                    f"Vendor: {vendor}\n\n"
                )
                
                # Update GUI periodically
                if len(self.hosts) % 5 == 0:
                    self.root.update()
        
        except Exception as e:
            self.append_details(f"Error parsing results: {str(e)}\n")
    
    def get_xml_field(self, text, pattern, default='Unknown'):
        """Helper to extract field from XML"""
        match = re.search(pattern, text)
        return match.group(1) if match else default
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.scan_button.config(text="Start Scan")
        self.progress.stop()
        self.status_label.config(text="Scan stopped")
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.append_details("\n[Scan stopped by user]\n")
    
    def clear_results(self):
        """Clear previous scan results"""
        self.hosts = []
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
    
    def append_details(self, text):
        """Append text to details window"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, text)
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)
    
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
