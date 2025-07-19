import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import socket
import threading
import time

class SSHManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Manager")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # SSH status
        self.ssh_running = False
        self.devices = []
        
        # Create GUI elements
        self.create_widgets()
        
        # Check SSH status initially
        self.check_ssh_status()
        
        # Start device monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_devices, daemon=True)
        self.monitor_thread.start()
    
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
        
        self.status_label = ttk.Label(status_frame, text="Checking status...", font=('Helvetica', 12))
        self.status_label.pack()
        
        # IP Address display
        ip_frame = ttk.LabelFrame(main_frame, text="Server Information", padding="10")
        ip_frame.pack(fill=tk.X, pady=5)
        
        self.ip_label = ttk.Label(ip_frame, text=self.get_ip_address())
        self.ip_label.pack()
        
        # Control buttons
        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start SSH", command=self.start_ssh)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop SSH", command=self.stop_ssh)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state=tk.DISABLED)
        
        # Connected devices
        devices_frame = ttk.LabelFrame(main_frame, text="Connected Devices", padding="10")
        devices_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.devices_tree = ttk.Treeview(devices_frame, columns=('ip', 'hostname'), show='headings')
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('hostname', text='Hostname')
        self.devices_tree.column('ip', width=150)
        self.devices_tree.column('hostname', width=250)
        self.devices_tree.pack(fill=tk.BOTH, expand=True)
        
        # Refresh button
        refresh_button = ttk.Button(main_frame, text="Refresh", command=self.refresh_devices)
        refresh_button.pack(pady=5)
    
    def get_ip_address(self):
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return f"Hostname: {hostname}\nIP Address: {ip_address}"
        except:
            return "Unable to get IP address"
    
    def check_ssh_status(self):
        try:
            result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
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
        except:
            self.ssh_running = False
            self.status_label.config(text="Unable to check SSH status", foreground='orange')
    
    def start_ssh(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'ssh'], check=True)
            messagebox.showinfo("Success", "SSH server started successfully")
            self.check_ssh_status()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to start SSH server")
    
    def stop_ssh(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'ssh'], check=True)
            messagebox.showinfo("Success", "SSH server stopped successfully")
            self.check_ssh_status()
            self.clear_devices()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to stop SSH server")
    
    def get_connected_devices(self):
        try:
            # Get SSH connections using netstat
            result = subprocess.run(['netstat', '-tnpa'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            devices = []
            for line in lines:
                if 'ssh' in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    ip_port = parts[4].split(':')[0]  # Get IP without port
                    
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip_port)[0]
                    except:
                        hostname = "Unknown"
                    
                    devices.append((ip_port, hostname))
            
            return devices
        except:
            return []
    
    def update_devices_list(self):
        self.devices = self.get_connected_devices()
        
        # Clear current items
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Add new items
        for ip, hostname in self.devices:
            self.devices_tree.insert('', tk.END, values=(ip, hostname))
    
    def clear_devices(self):
        self.devices = []
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
    
    def refresh_devices(self):
        if self.ssh_running:
            self.update_devices_list()
        else:
            self.clear_devices()
    
    def monitor_devices(self):
        while True:
            if self.ssh_running:
                self.update_devices_list()
            time.sleep(5)

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHManager(root)
    root.mainloop()