import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import socket
import threading
import time
import netifaces

class SSHManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Manager")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        
        # SSH status
        self.ssh_running = False
        self.devices = []
        self.last_update_time = "Never"
        
        # Create GUI elements
        self.create_widgets()
        
        # Check SSH status initially
        self.update_status()
        
        # Start monitoring threads
        self.start_monitoring_threads()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="SSH Manager", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="SSH Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)
        
        # Status display with update time
        self.status_display = ttk.Frame(status_frame)
        self.status_display.pack(fill=tk.X)
        
        self.status_label = ttk.Label(self.status_display, text="Checking status...", font=('Helvetica', 12))
        self.status_label.pack(side=tk.LEFT)
        
        self.last_update_label = ttk.Label(self.status_display, text="Last updated: Never", font=('Helvetica', 8))
        self.last_update_label.pack(side=tk.RIGHT)
        
        # Detailed status button
        self.details_button = ttk.Button(status_frame, text="Show Detailed Status", command=self.show_detailed_status)
        self.details_button.pack(pady=5)
        
        # IP Address display
        ip_frame = ttk.LabelFrame(main_frame, text="Server Information", padding="10")
        ip_frame.pack(fill=tk.X, pady=5)
        
        self.ip_label = ttk.Label(ip_frame, text=self.get_network_info())
        self.ip_label.pack()
        
        # Control buttons
        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start SSH", command=self.start_ssh)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop SSH", command=self.stop_ssh)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state=tk.DISABLED)
        
        # Refresh controls
        refresh_frame = ttk.Frame(main_frame)
        refresh_frame.pack(fill=tk.X, pady=5)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = ttk.Checkbutton(refresh_frame, text="Auto-refresh", variable=self.auto_refresh_var)
        auto_refresh_check.pack(side=tk.LEFT, padx=5)
        
        refresh_button = ttk.Button(refresh_frame, text="Refresh Now", command=self.manual_refresh)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        # Connected devices
        devices_frame = ttk.LabelFrame(main_frame, text="Connected Devices", padding="10")
        devices_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.devices_tree = ttk.Treeview(devices_frame, columns=('ip', 'hostname'), show='headings')
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('hostname', text='Hostname')
        self.devices_tree.column('ip', width=150)
        self.devices_tree.column('hostname', width=250)
        self.devices_tree.pack(fill=tk.BOTH, expand=True)
    
    def start_monitoring_threads(self):
        # Status monitoring thread
        self.status_thread = threading.Thread(target=self.monitor_status, daemon=True)
        self.status_thread.start()
        
        # Device monitoring thread
        self.devices_thread = threading.Thread(target=self.monitor_devices, daemon=True)
        self.devices_thread.start()
    
    def update_status(self):
        try:
            result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
            current_time = time.strftime("%H:%M:%S", time.localtime())
            self.last_update_time = current_time
            
            if result.stdout.strip() == 'active':
                self.ssh_running = True
                self.status_label.config(text="SSH Server: RUNNING", foreground='green')
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
            else:
                self.ssh_running = False
                self.status_label.config(text="SSH Server: STOPPED", foreground='red')
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
            
            self.last_update_label.config(text=f"Last updated: {current_time}")
        except Exception as e:
            self.status_label.config(text=f"Status check failed: {str(e)}", foreground='orange')
    
    def monitor_status(self):
        while True:
            if self.auto_refresh_var.get():
                self.update_status()
            time.sleep(5)  # Update every 5 seconds
    
    def manual_refresh(self):
        self.update_status()
        self.update_devices_list()
    
    def get_network_info(self):
        try:
            hostname = socket.gethostname()
            interfaces = netifaces.interfaces()
            ip_addresses = []
            
            for interface in interfaces:
                if interface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip_addresses.append(addr_info['addr'])
            
            if not ip_addresses:
                return f"Hostname: {hostname}\nIP Address: Not connected to network"
            
            return f"Hostname: {hostname}\nIP Address(es): {', '.join(ip_addresses)}"
        except Exception as e:
            return f"Error getting network info: {str(e)}"
    
    def get_detailed_ssh_status(self):
        try:
            result = subprocess.run(['sudo', 'systemctl', 'status', 'ssh'], capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error getting detailed status:\n{e.stdout}\n{e.stderr}"
    
    def show_detailed_status(self):
        status_window = tk.Toplevel(self.root)
        status_window.title("SSH Service Details")
        status_window.geometry("600x400")
        
        status_text = scrolledtext.ScrolledText(status_window, wrap=tk.WORD)
        status_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        status = self.get_detailed_ssh_status()
        status_text.insert(tk.END, f"Status at {time.strftime('%H:%M:%S')}\n\n{status}")
        status_text.config(state=tk.DISABLED)
        
        close_button = ttk.Button(status_window, text="Close", command=status_window.destroy)
        close_button.pack(pady=10)
    
    def start_ssh(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'ssh'], check=True)
            messagebox.showinfo("Success", "SSH server started successfully")
            self.update_status()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to start SSH server")
    
    def stop_ssh(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'ssh'], check=True)
            messagebox.showinfo("Success", "SSH server stopped successfully")
            self.update_status()
            self.clear_devices()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to stop SSH server")
    
    def get_connected_devices(self):
        try:
            result = subprocess.run(['netstat', '-tnpa'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            devices = []
            for line in lines:
                if 'ssh' in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    ip_port = parts[4].split(':')[0]
                    
                    try:
                        hostname = socket.gethostbyaddr(ip_port)[0]
                    except:
                        hostname = "Unknown"
                    
                    devices.append((ip_port, hostname))
            
            return devices
        except:
            return []
    
    def update_devices_list(self):
        if not self.ssh_running:
            self.clear_devices()
            return
            
        self.devices = self.get_connected_devices()
        
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        for ip, hostname in self.devices:
            self.devices_tree.insert('', tk.END, values=(ip, hostname))
    
    def clear_devices(self):
        self.devices = []
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
    
    def monitor_devices(self):
        while True:
            if self.auto_refresh_var.get() and self.ssh_running:
                self.update_devices_list()
            time.sleep(5)

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHManager(root)
    root.mainloop()
