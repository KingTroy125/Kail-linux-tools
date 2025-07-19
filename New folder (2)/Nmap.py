import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import socket
import threading
import time
import netifaces
import re
from datetime import datetime

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Scan variables
        self.scanning = False
        self.scan_thread = None
        self.network_info = {}
        self.devices = []
        
        # Create GUI elements
        self.create_widgets()
        
        # Get network info initially
        self.update_network_info()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Network Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Network info frame
        info_frame = ttk.LabelFrame(main_frame, text="Network Information", padding="10")
        info_frame.pack(fill=tk.X, pady=5)
        
        self.info_label = ttk.Label(info_frame, text="", font=('Helvetica', 10))
        self.info_label.pack()
        
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
        results_frame = ttk.LabelFrame(main_frame, text="Discovered Devices", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for devices
        self.devices_tree = ttk.Treeview(results_frame, columns=('ip', 'mac', 'hostname', 'vendor', 'os'), show='headings')
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('mac', text='MAC Address')
        self.devices_tree.heading('hostname', text='Hostname')
        self.devices_tree.heading('vendor', text='Vendor')
        self.devices_tree.heading('os', text='OS Guess')
        
        # Set column widths
        self.devices_tree.column('ip', width=120, anchor=tk.W)
        self.devices_tree.column('mac', width=120, anchor=tk.W)
        self.devices_tree.column('hostname', width=150, anchor=tk.W)
        self.devices_tree.column('vendor', width=200, anchor=tk.W)
        self.devices_tree.column('os', width=200, anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.devices_tree.pack(fill=tk.BOTH, expand=True)
        
        # Details frame
        details_frame = ttk.LabelFrame(main_frame, text="Scan Details", padding="10")
        details_frame.pack(fill=tk.BOTH, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=8)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
    
    def update_network_info(self):
        """Get and display network interface information"""
        try:
            self.network_info = self.get_network_interfaces()
            info_text = ""
            for interface, data in self.network_info.items():
                info_text += f"Interface: {interface}\n"
                info_text += f"  IP: {data.get('ip', 'N/A')}\n"
                info_text += f"  Netmask: {data.get('netmask', 'N/A')}\n"
                info_text += f"  Network: {data.get('network', 'N/A')}\n\n"
            self.info_label.config(text=info_text.strip())
        except Exception as e:
            self.info_label.config(text=f"Error getting network info: {str(e)}")
    
    def get_network_interfaces(self):
        """Get all network interfaces with IP addresses"""
        interfaces = {}
        for interface in netifaces.interfaces():
            if interface == 'lo':
                continue  # Skip loopback
            
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info.get('addr', '')
                netmask = ip_info.get('netmask', '')
                
                # Calculate network address
                if ip and netmask:
                    network = self.calculate_network(ip, netmask)
                else:
                    network = 'N/A'
                
                interfaces[interface] = {
                    'ip': ip,
                    'netmask': netmask,
                    'network': network
                }
        
        return interfaces
    
    def calculate_network(self, ip, netmask):
        """Calculate network address from IP and netmask"""
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        
        network_parts = []
        for i in range(4):
            network_parts.append(str(ip_parts[i] & mask_parts[i]))
        
        return '.'.join(network_parts) + '/24'  # Assume /24 for scanning
    
    def toggle_scan(self):
        """Start or stop scanning"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start network scan"""
        if not self.network_info:
            messagebox.showerror("Error", "No network interfaces found")
            return
        
        # Choose the first non-empty network
        target_network = None
        for data in self.network_info.values():
            if data.get('network'):
                target_network = data['network']
                break
        
        if not target_network:
            messagebox.showerror("Error", "Could not determine network to scan")
            return
        
        self.scanning = True
        self.scan_button.config(text="Stop Scan")
        self.progress.start()
        self.status_label.config(text="Scanning...")
        self.clear_results()
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_nmap_scan,
            args=(target_network,),
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
            # In a real app, you'd need a way to actually stop nmap
            self.append_details("\n[Scan stopped by user]\n")
    
    def run_nmap_scan(self, target):
        """Run nmap scan and parse results"""
        try:
            self.append_details(f"Starting scan of {target} at {datetime.now().strftime('%H:%M:%S')}\n")
            
            # Run nmap command (adjust arguments as needed)
            command = [
                'nmap',
                '-sn',           # Ping scan
                '-n',            # No DNS resolution
                '-PE',           # ICMP echo
                '-PS22,80,443',  # TCP SYN ping on common ports
                '-PA22,80,443',  # TCP ACK ping on common ports
                '-PY22,80,443',  # SCTP ping
                '-PP',           # ICMP timestamp
                '-PM',           # ICMP netmask
                '-oX', '-',      # Output XML to stdout
                target
            ]
            
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
        # This is a simplified parser - consider using python-nmap library for robust parsing
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
            
            # Add to devices list
            self.devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'os': os_guess
            })
            
            # Add to treeview
            self.devices_tree.insert('', tk.END, values=(
                ip, mac, hostname, vendor, os_guess
            ))
            
            # Add to details
            self.append_details(
                f"Host: {ip} ({hostname})\n"
                f"  MAC: {mac}\n"
                f"  Vendor: {vendor}\n"
                f"  OS Guess: {os_guess}\n\n"
            )
    
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
