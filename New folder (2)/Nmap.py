import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import subprocess
import threading
from datetime import datetime
import ipaddress

class PingScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap Ping Scanner")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Scan variables
        self.scanning = False
        self.scan_thread = None
        self.sudo_password = None
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Nmap Ping Scanner", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Target input frame
        input_frame = ttk.LabelFrame(main_frame, text="Network to Scan", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # Target entry
        ttk.Label(input_frame, text="Network (e.g., 192.168.1.0/24):").pack(side=tk.LEFT, padx=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(input_frame, textvariable=self.target_var, width=20)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "192.168.1.0/24")
        
        # Scan type selection
        scan_frame = ttk.Frame(main_frame, padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        self.scan_type = tk.StringVar(value='sP')
        
        ttk.Radiobutton(scan_frame, text="-sP (Ping Scan)", variable=self.scan_type, value='sP').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(scan_frame, text="-sn (No Port Scan)", variable=self.scan_type, value='sn').pack(side=tk.LEFT, padx=5)
        
        # Control frame
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan_wrapper)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
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
    
    def start_scan_wrapper(self):
        """Wrapper to get sudo password before starting scan"""
        if self.scanning:
            self.stop_scan()
            return
        
        self.sudo_password = simpledialog.askstring("Sudo Password", 
                                                  "Enter your sudo password:", 
                                                  show='*')
        if self.sudo_password is None:  # User cancelled
            return
        
        self.start_scan()
    
    def validate_target(self, target_str):
        """Validate the network address input"""
        try:
            network = ipaddress.IPv4Network(target_str.strip(), strict=False)
            return str(network)
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid network in CIDR notation\nExample: 192.168.1.0/24")
            return None
    
    def start_scan(self):
        """Start network scan"""
        target = self.validate_target(self.target_var.get())
        if not target:
            return
        
        self.scanning = True
        self.scan_button.config(text="Stop Scan")
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
        """Run the nmap ping scan with sudo"""
        try:
            scan_type = self.scan_type.get()
            command = ['sudo', '-S', 'nmap', f'-{scan_type}', target]
            
            self.append_output(f"Running command: {' '.join(command)}\n")
            self.append_output(f"Scan started at {datetime.now().strftime('%H:%M:%S')}\n")
            self.append_output("-" * 50 + "\n")
            
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Send sudo password
            process.stdin.write(self.sudo_password + "\n")
            process.stdin.flush()
            
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
                    self.append_output("\n" + "-" * 50 + "\n")
                    self.append_output(f"Scan completed at {datetime.now().strftime('%H:%M:%S')}\n")
                    self.status_label.config(text="Scan completed")
                else:
                    error = process.stderr.read()
                    self.append_output(f"\nError:\n{error}\n")
                    self.status_label.config(text="Scan failed")
            
        except Exception as e:
            self.append_output(f"\nError: {str(e)}\n")
            self.status_label.config(text="Scan failed")
        finally:
            if self.scanning:
                self.scanning = False
                self.scan_button.config(text="Start Scan")
                self.sudo_password = None  # Clear password after use
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.scan_button.config(text="Start Scan")
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
