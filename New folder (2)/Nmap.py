import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import re
from datetime import datetime
import ipaddress

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Address Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Scan variables
        self.scanning = False
        self.scan_thread = None
        self.devices = []
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="IP Address Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Scan Target", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Target input
        ttk.Label(input_frame, text="Enter IP or Range:").pack(side=tk.LEFT, padx=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(input_frame, textvariable=self.target_var, width=25)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "192.168.1.1")  # Default value
        
        # Examples
        examples = ttk.Label(input_frame, 
                           text="Examples: 192.168.1.1, 192.168.1.1-100, 192.168.1.0/24",
                           font=('Helvetica', 9))
        examples.pack(side=tk.LEFT, padx=5)
        
        # Control frame
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.toggle_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Scan options
        ttk.Label(control_frame, text="Scan Type:").pack(side=tk.LEFT, padx=5)
        self.scan_type_var = tk.StringVar(value='quick')
        ttk.Radiobutton(control_frame, text="Quick", variable=self.scan_type_var, value='quick').pack(side=tk.LEFT)
        ttk.Radiobutton(control_frame, text="Detailed", variable=self.scan_type_var, value='detailed').pack(side=tk.LEFT, padx=5)
        
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
                                       columns=('ip', 'status', 'hostname', 'mac', 'ports'), 
                                       show='headings')
        self.results_tree.heading('ip', text='IP Address')
        self.results_tree.heading('status', text='Status')
        self.results_tree.heading('hostname', text='Hostname')
        self.results_tree.heading('mac', text='MAC Address')
        self.results_tree.heading('ports', text='Open Ports')
        
        # Set column widths
        self.results_tree.column('ip', width=120, anchor=tk.W)
        self.results_tree.column('status', width=80, anchor=tk.W)
        self.results_tree.column('hostname', width=150, anchor=tk.W)
        self.results_tree.column('mac', width=120, anchor=tk.W)
        self.results_tree.column('ports', width=200, anchor=tk.W)
        
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
        
        # Set focus to target entry
        self.target_entry.focus()
    
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
        
        # Determine scan type
        scan_type = self.scan_type_var.get()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, scan_type),
            daemon=True
        )
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.scan_button.config(text="Start Scan")
        self.progress.stop()
        self.status_label.config(text="Scan stopped")
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.append_details("\n[Scan stopped by user]\n")
    
    def run_scan(self, target, scan_type):
        """Run the nmap scan with appropriate parameters"""
        try:
            self.append_details(f"Starting {scan_type} scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            # Base command
            command = ['sudo', 'nmap', '-oX', '-', '-n']
            
            # Add scan type specific options
            if scan_type == 'quick':
                command.extend(['-sn', '-PE', '-PS22,80,443'])
            else:  # detailed scan
                command.extend(['-T4', '-A', '-v'])
            
            command.append(target)
            
            self.append_details("Command: " + ' '.join(command) + "\n")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.scanning:  # Only process if scan wasn't stopped
                self.parse_scan_output(result.stdout, scan_type)
                self.append_details(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                self.status_label.config(text=f"Scan completed - {len(self.devices)} hosts found")
            
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
    
    def parse_scan_output(self, xml_output, scan_type):
        """Parse nmap XML output based on scan type"""
        try:
            if scan_type == 'quick':
                self.parse_ping_scan(xml_output)
            else:
                self.parse_detailed_scan(xml_output)
        except Exception as e:
            self.append_details(f"Error parsing output: {str(e)}\n")
    
    def parse_ping_scan(self, xml_output):
        """Parse ping scan (-sn) results"""
        hosts = re.findall(r'<host .*?>.*?</host>', xml_output, re.DOTALL)
        self.append_details(f"\nFound {len(hosts)} active hosts\n")
        
        for host in hosts:
            # Get IP address
            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"/>', host)
            ip = ip_match.group(1) if ip_match else 'Unknown'
            
            # Get status
            status = 'Up'
            
            # Get MAC address and vendor
            mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"(?: vendor="([^"]+)")?', host)
            if mac_match:
                mac = mac_match.group(1)
                vendor = mac_match.group(2) if mac_match.group(2) else 'Unknown'
            else:
                mac = 'Unknown'
                vendor = 'Unknown'
            
            # Get hostname
            hostname_match = re.search(r'<hostname name="([^"]+)"', host)
            hostname = hostname_match.group(1) if hostname_match else 'Unknown'
            
            # Add to results
            self.devices.append({
                'ip': ip,
                'status': status,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'ports': 'N/A (ping scan)'
            })
            
            self.results_tree.insert('', tk.END, values=(
                ip, status, hostname, mac, 'N/A (ping scan)'
            ))
            
            self.append_details(
                f"Host: {ip} ({hostname})\n"
                f"  Status: {status}\n"
                f"  MAC: {mac} ({vendor})\n\n"
            )
            
            if len(self.devices) % 5 == 0:
                self.root.update()
    
    def parse_detailed_scan(self, xml_output):
        """Parse detailed scan results"""
        hosts = re.findall(r'<host .*?>.*?</host>', xml_output, re.DOTALL)
        self.append_details(f"\nFound {len(hosts)} hosts\n")
        
        for host in hosts:
            # Get IP address
            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"/>', host)
            ip = ip_match.group(1) if ip_match else 'Unknown'
            
            # Get status
            status_match = re.search(r'<status state="([^"]+)"', host)
            status = status_match.group(1).capitalize() if status_match else 'Unknown'
            
            # Skip if host is down
            if status.lower() != 'up':
                continue
            
            # Get MAC address and vendor
            mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"(?: vendor="([^"]+)")?', host)
            if mac_match:
                mac = mac_match.group(1)
                vendor = mac_match.group(2) if mac_match.group(2) else 'Unknown'
            else:
                mac = 'Unknown'
                vendor = 'Unknown'
            
            # Get hostname
            hostname_match = re.search(r'<hostname name="([^"]+)"', host)
            hostname = hostname_match.group(1) if hostname_match else 'Unknown'
            
            # Get open ports
            ports = []
            port_matches = re.finditer(r'<port protocol="[^"]+" portid="([^"]+)">.*?<state state="([^"]+)".*?<service name="([^"]+)"', host, re.DOTALL)
            for match in port_matches:
                if match.group(2) == 'open':
                    ports.append(f"{match.group(1)}/{match.group(3)}")
            ports_str = ', '.join(ports) if ports else 'None'
            
            # Add to results
            self.devices.append({
                'ip': ip,
                'status': status,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'ports': ports_str
            })
            
            self.results_tree.insert('', tk.END, values=(
                ip, status, hostname, mac, ports_str
            ))
            
            self.append_details(
                f"Host: {ip} ({hostname})\n"
                f"  Status: {status}\n"
                f"  MAC: {mac} ({vendor})\n"
                f"  Open Ports: {ports_str}\n\n"
            )
            
            if len(self.devices) % 5 == 0:
                self.root.update()
    
    def clear_results(self):
        """Clear previous scan results"""
        self.devices = []
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
    app = NetworkScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
