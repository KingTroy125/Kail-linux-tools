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
        self.root.title("Network Ping Scanner")
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
        title_label = ttk.Label(main_frame, text="Network Ping Scanner (nmap -sP)", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Network input frame
        input_frame = ttk.LabelFrame(main_frame, text="Network to Scan", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Network address input
        ttk.Label(input_frame, text="Network Address (e.g., 192.168.1.0/24):").pack(side=tk.LEFT, padx=5)
        self.network_var = tk.StringVar()
        self.network_entry = ttk.Entry(input_frame, textvariable=self.network_var, width=20)
        self.network_entry.pack(side=tk.LEFT, padx=5)
        self.network_entry.insert(0, "192.168.1.0/24")  # Default value
        
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
        
        # Treeview for devices
        self.devices_tree = ttk.Treeview(results_frame, columns=('ip', 'mac', 'hostname', 'vendor'), show='headings')
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('mac', text='MAC Address')
        self.devices_tree.heading('hostname', text='Hostname')
        self.devices_tree.heading('vendor', text='Vendor')
        
        # Set column widths
        self.devices_tree.column('ip', width=150, anchor=tk.W)
        self.devices_tree.column('mac', width=150, anchor=tk.W)
        self.devices_tree.column('hostname', width=200, anchor=tk.W)
        self.devices_tree.column('vendor', width=250, anchor=tk.W)
        
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
            messagebox.showerror("Invalid Input", 
                               "Please enter a valid network address with CIDR notation\n"
                               "Example: 192.168.1.0/24 or 10.0.0.0/16")
            return None
    
    def toggle_scan(self):
        """Start or stop scanning"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start network ping scan"""
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
        self.status_label.config(text=f"Scanning {network}...")
        self.clear_results()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_ping_scan,
            args=(str(network),),
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
    
    def run_ping_scan(self, target):
        """Run nmap ping scan (-sP) and parse results"""
        try:
            self.append_details(f"Starting ping scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            # Nmap ping scan command
            command = [
                'sudo', 'nmap',
                '-sP',  # Ping scan
                '-n',   # No DNS resolution
                target
            ]
            
            self.append_details("Running command: sudo nmap -sP " + target + "\n")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.scanning:  # Only process if scan wasn't stopped
                self.parse_ping_scan_output(result.stdout)
                self.append_details(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                self.status_label.config(text=f"Found {len(self.devices)} hosts")
            
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
    
    def parse_ping_scan_output(self, nmap_output):
        """Parse nmap ping scan (-sP) output"""
        try:
            # Split output by host
            host_blocks = re.split(r'Nmap scan report for ', nmap_output)[1:]
            self.append_details(f"\nFound {len(host_blocks)} hosts\n")
            
            for block in host_blocks:
                # Get IP address (first line)
                ip_match = re.match(r'([\d.]+)', block)
                ip = ip_match.group(1) if ip_match else 'Unknown'
                
                # Get MAC address
                mac_match = re.search(r'MAC Address: ([\w:]+) \((.*?)\)', block)
                if mac_match:
                    mac = mac_match.group(1)
                    vendor = mac_match.group(2)
                else:
                    mac = 'Unknown'
                    vendor = 'Unknown'
                
                # Get hostname (if available)
                hostname_match = re.search(r'\(([\w\-\.]+)\)', block.split('\n')[0])
                hostname = hostname_match.group(1) if hostname_match else 'Unknown'
                
                # Add to devices list
                self.devices.append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor
                })
                
                # Add to treeview
                self.devices_tree.insert('', tk.END, values=(
                    ip, mac, hostname, vendor
                ))
                
                # Add to details
                self.append_details(
                    f"Host: {ip}\n"
                    f"  Hostname: {hostname}\n"
                    f"  MAC: {mac}\n"
                    f"  Vendor: {vendor}\n\n"
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
