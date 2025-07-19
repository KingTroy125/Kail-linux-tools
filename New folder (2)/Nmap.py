import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import re
from datetime import datetime
import ipaddress

class NmapScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap Scanner")
        self.root.geometry("1000x800")
        self.root.resizable(True, True)
        
        # Scan variables
        self.scanning = False
        self.scan_thread = None
        self.results = []
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Nmap Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Target input frame
        input_frame = ttk.LabelFrame(main_frame, text="Scan Target", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Target entry
        ttk.Label(input_frame, text="IP/Range:").pack(side=tk.LEFT, padx=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(input_frame, textvariable=self.target_var, width=25)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "192.168.1.1")
        
        # Examples
        ttk.Label(input_frame, 
                 text="Examples: 192.168.1.1, 192.168.1.1-100, 192.168.1.0/24",
                 font=('Helvetica', 9)).pack(side=tk.LEFT, padx=5)
        
        # Scan type selection
        scan_frame = ttk.LabelFrame(main_frame, text="Scan Type", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        self.scan_type = tk.StringVar(value='sn')
        
        # Scan type buttons
        types = [
            ('Ping Scan (-sn)', 'sn'),
            ('Quick Scan (-T4 -F)', 'quick'),
            ('Full Scan (-A)', 'full'),
            ('Port Range (-p 1-1000)', 'ports'),
            ('OS Detection (-O)', 'os'),
            ('Service Detection (-sV)', 'service')
        ]
        
        for i, (text, mode) in enumerate(types):
            btn = ttk.Radiobutton(scan_frame, text=text, variable=self.scan_type, value=mode)
            btn.grid(row=i//3, column=i%3, sticky='w', padx=5, pady=2)
        
        # Custom scan frame
        custom_frame = ttk.Frame(scan_frame)
        custom_frame.grid(row=2, column=2, columnspan=1, sticky='ew')
        ttk.Label(custom_frame, text="Custom:").pack(side=tk.LEFT)
        self.custom_scan_var = tk.StringVar()
        self.custom_scan_entry = ttk.Entry(custom_frame, textvariable=self.custom_scan_var, width=15)
        self.custom_scan_entry.pack(side=tk.LEFT, padx=5)
        self.custom_scan_entry.insert(0, "-sS -p 22,80,443")
        
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
        
        # Treeview for results
        self.results_tree = ttk.Treeview(results_frame, 
                                       columns=('ip', 'status', 'hostname', 'ports', 'os', 'service'), 
                                       show='headings')
        
        # Configure columns
        columns = [
            ('ip', 'IP Address', 120),
            ('status', 'Status', 80),
            ('hostname', 'Hostname', 150),
            ('ports', 'Open Ports', 200),
            ('os', 'OS Guess', 150),
            ('service', 'Services', 200)
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
    
    def get_scan_command(self, target):
        """Return the appropriate nmap command based on selected scan type"""
        scan_type = self.scan_type.get()
        
        base_cmd = ['sudo', 'nmap', '-oX', '-', '-n', target]
        
        if scan_type == 'sn':
            return base_cmd + ['-sn']
        elif scan_type == 'quick':
            return base_cmd + ['-T4', '-F']
        elif scan_type == 'full':
            return base_cmd + ['-A', '-v']
        elif scan_type == 'ports':
            return base_cmd + ['-p', '1-1000']
        elif scan_type == 'os':
            return base_cmd + ['-O']
        elif scan_type == 'service':
            return base_cmd + ['-sV']
        else:  # custom
            custom = self.custom_scan_var.get().strip()
            return base_cmd + custom.split()
    
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
            target=self.run_scan,
            args=(target,),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, target):
        """Run the nmap scan with selected options"""
        try:
            command = self.get_scan_command(target)
            scan_type = self.scan_type.get()
            
            self.append_details(f"Starting {scan_type} scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            self.append_details("Command: " + ' '.join(command) + "\n")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.scanning:  # Only process if scan wasn't stopped
                self.parse_results(result.stdout, scan_type)
                self.append_details(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                self.status_label.config(text=f"Scan completed - {len(self.results)} hosts found")
            
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
    
    def parse_results(self, xml_output, scan_type):
        """Parse nmap XML output based on scan type"""
        try:
            hosts = re.findall(r'<host .*?>.*?</host>', xml_output, re.DOTALL)
            self.append_details(f"\nFound {len(hosts)} hosts\n")
            
            for host in hosts:
                # Get common fields
                ip = self.get_xml_field(host, r'<address addr="([^"]+)" addrtype="ipv4"/>')
                status = self.get_xml_field(host, r'<status state="([^"]+)"', 'status').capitalize()
                
                # Skip if host is down (unless it's a ping scan)
                if status.lower() != 'up' and scan_type != 'sn':
                    continue
                
                # Get additional fields
                hostname = self.get_xml_field(host, r'<hostname name="([^"]+)"')
                mac = self.get_xml_field(host, r'<address addr="([^"]+)" addrtype="mac"/>')
                vendor = self.get_xml_field(host, r'vendor="([^"]+)"')
                os = self.get_xml_field(host, r'<osclass type="([^"]+)"')
                
                # Get ports and services
                ports = []
                port_matches = re.finditer(
                    r'<port protocol="[^"]+" portid="([^"]+)">.*?<state state="([^"]+)".*?<service name="([^"]+)"', 
                    host, re.DOTALL)
                
                for match in port_matches:
                    if match.group(2) == 'open':
                        ports.append(f"{match.group(1)}/{match.group(3)}")
                
                ports_str = ', '.join(ports) if ports else 'None'
                
                # Add to results
                self.results.append({
                    'ip': ip,
                    'status': status,
                    'hostname': hostname,
                    'ports': ports_str,
                    'os': os,
                    'service': vendor
                })
                
                # Add to treeview
                self.results_tree.insert('', tk.END, values=(
                    ip, status, hostname, ports_str, os, vendor
                ))
                
                # Add to details
                self.append_details(
                    f"Host: {ip} ({hostname})\n"
                    f"Status: {status}\n"
                    f"MAC: {mac} ({vendor})\n"
                    f"OS: {os}\n"
                    f"Open Ports: {ports_str}\n\n"
                )
                
                # Update GUI periodically
                if len(self.results) % 5 == 0:
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
        self.results = []
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
    app = NmapScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
