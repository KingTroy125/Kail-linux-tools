import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import re
from datetime import datetime
import ipaddress

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("1000x800")
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
        title_label = ttk.Label(main_frame, text="Network Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Network input frame
        input_frame = ttk.LabelFrame(main_frame, text="Network to Scan", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Network address input
        ttk.Label(input_frame, text="Network Address (e.g., 192.168.1.0/24):").pack(side=tk.LEFT, padx=5)
        self.network_var = tk.StringVar()
        self.network_entry = ttk.Entry(input_frame, textvariable=self.network_var, width=20)
        self.network_entry.pack(side=tk.LEFT, padx=5)
        
        # Example label
        ttk.Label(input_frame, text="Example: 192.168.1.0/24", font=('Helvetica', 9)).pack(side=tk.LEFT, padx=5)
        
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
        ttk.Radiobutton(control_frame, text="Full", variable=self.scan_type_var, value='full').pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Status label
        self.status_label = ttk.Label(control_frame, text="Ready", font=('Helvetica', 10))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Discovered Devices", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for devices
        self.devices_tree = ttk.Treeview(results_frame, columns=('ip', 'mac', 'hostname', 'vendor', 'os', 'ports'), show='headings')
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('mac', text='MAC Address')
        self.devices_tree.heading('hostname', text='Hostname')
        self.devices_tree.heading('vendor', text='Vendor')
        self.devices_tree.heading('os', text='OS Guess')
        self.devices_tree.heading('ports', text='Open Ports')
        
        # Set column widths
        self.devices_tree.column('ip', width=120, anchor=tk.W)
        self.devices_tree.column('mac', width=120, anchor=tk.W)
        self.devices_tree.column('hostname', width=150, anchor=tk.W)
        self.devices_tree.column('vendor', width=150, anchor=tk.W)
        self.devices_tree.column('os', width=150, anchor=tk.W)
        self.devices_tree.column('ports', width=150, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.devices_tree.pack(fill=tk.BOTH, expand=True)
        
        # Details frame
        details_frame = ttk.LabelFrame(main_frame, text="Scan Details", padding="10")
        details_frame.pack(fill=tk.BOTH, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
        
        # Set focus to network entry
        self.network_entry.focus()
    
    def validate_network(self, network_str):
        """Validate the network address input"""
        try:
            network = ipaddress.IPv4Network(network_str, strict=False)
            return network
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid network address with CIDR notation\nExample: 192.168.1.0/24")
            return None
    
    def toggle_scan(self):
        """Start or stop scanning"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start network scan"""
        network_str = self.network_var.get().strip()
        if not network_str:
            messagebox.showerror("Error", "Please enter a network address to scan")
            return
        
        network = self.validate_network(network_str)
        if not network:
            return
        
        self.scanning = True
        self.scan_button.config(text="Stop Scan")
        self.progress.start()
        self.status_label.config(text="Scanning...")
        self.clear_results()
        
        # Determine scan type
        scan_type = self.scan_type_var.get()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_nmap_scan,
            args=(str(network), scan_type),
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
    
    def run_nmap_scan(self, target, scan_type):
        """Run nmap scan and parse results"""
        try:
            self.append_details(f"Starting {scan_type} scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            # Base nmap command
            command = ['nmap', '-oX', '-', '-n']
            
            # Add scan type specific options
            if scan_type == 'quick':
                command.extend(['-sn', '-PE', '-PS22,80,443', '-PA22,80,443'])
            else:  # full scan
                command.extend(['-T4', '-A', '-v', '-Pn', '--min-parallelism 100'])
            
            command.append(target)
            
            self.append_details("Running command: " + ' '.join(command) + "\n")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.scanning:  # Only process if scan wasn't stopped
                self.parse_nmap_output(result.stdout)
                self.append_details(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                self.status_label.config(text="Scan completed")
            
        except subprocess.CalledProcessError as e:
            self.append_details(f"Error running nmap:\n{e.stderr}\n")
            self.status_label.config(text="Scan failed")
        except Exception as e:
            self.append_details(f"Unexpected error: {str(e)}\n")
            self.status_label.config(text="Scan failed")
        finally:
            if self.scanning:
                self.scanning = False
                self.scan_button.config(text="Start Scan")
                self.progress.stop()
    
    def parse_nmap_output(self, xml_output):
        """Parse nmap XML output and update GUI"""
        try:
            hosts = re.findall(r'<host .*?>.*?</host>', xml_output, re.DOTALL)
            self.append_details(f"\nFound {len(hosts)} hosts\n")
            
            for host in hosts:
                # Get IP address
                ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"/>', host)
                ip = ip_match.group(1) if ip_match else 'Unknown'
                
                # Get MAC address
                mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"/>', host)
                mac = mac_match.group(1) if mac_match else 'Unknown'
                
                # Get vendor
                vendor_match = re.search(r'<address addr="[^"]+" addrtype="mac" vendor="([^"]+)"/>', host)
                vendor = vendor_match.group(1) if vendor_match else 'Unknown'
                
                # Get hostname
                hostname_match = re.search(r'<hostname name="([^"]+)"', host)
                hostname = hostname_match.group(1) if hostname_match else 'Unknown'
                
                # Get OS guess
                os_match = re.search(r'<osclass type="([^"]+)"', host)
                os_guess = os_match.group(1) if os_match else 'Unknown'
                
                # Get open ports
                ports = []
                port_matches = re.finditer(r'<port protocol="[^"]+" portid="([^"]+)">.*?<state state="([^"]+)".*?<service name="([^"]+)"', host, re.DOTALL)
                for match in port_matches:
                    if match.group(2) == 'open':
                        ports.append(f"{match.group(1)}/{match.group(3)}")
                ports_str = ', '.join(ports) if ports else 'None'
                
                # Add to devices list
                self.devices.append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'os': os_guess,
                    'ports': ports_str
                })
                
                # Add to treeview
                self.devices_tree.insert('', tk.END, values=(
                    ip, mac, hostname, vendor, os_guess, ports_str
                ))
                
                # Add to details
                self.append_details(
                    f"Host: {ip} ({hostname})\n"
                    f"  MAC: {mac} ({vendor})\n"
                    f"  OS Guess: {os_guess}\n"
                    f"  Open Ports: {ports_str}\n\n"
                )
                
                # Update GUI periodically
                if len(self.devices) % 5 == 0:
                    self.root.update()
        
        except Exception as e:
            self.append_details(f"Error parsing nmap output: {str(e)}\n")
    
    def clear_results(self):
        """Clear previous scan results"""
        self.devices = []
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
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
