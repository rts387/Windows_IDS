import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
import queue
from ids_core import WindowsIDS
import logging
import json

class IDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Intrusion Detection System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        self.ids = None
        self.running = False
        self.alert_queue = queue.Queue()
        
        # Set up custom logging to capture alerts
        self.setup_custom_logging()
        
        self.setup_gui()
        self.setup_styles()
        
        # Start alert processing
        self.process_alerts()
        self.update_network_stats()
        
    def setup_custom_logging(self):
        """Capture all log messages and send them to the GUI"""
        class GUILogHandler(logging.Handler):
            def __init__(self, alert_queue):
                super().__init__()
                self.alert_queue = alert_queue
                self.setFormatter(logging.Formatter('%(message)s'))
            
            def emit(self, record):
                try:
                    # Send the actual log message to GUI
                    message = record.getMessage()
                    level = record.levelname
                    
                    # Format for GUI display
                    if level == 'CRITICAL':
                        gui_message = f"CRITICAL: {message}"
                    elif level == 'WARNING':
                        gui_message = f"WARNING: {message}"
                    else:
                        gui_message = f"INFO: {message}"
                    
                    self.alert_queue.put(gui_message)
                except Exception as e:
                    print(f"Log handler error: {e}")
        
        # Add our custom handler to capture IDS logs
        self.gui_log_handler = GUILogHandler(self.alert_queue)
        self.gui_log_handler.setLevel(logging.INFO)
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles
        self.style.configure('Title.TLabel', 
                           background='#2b2b2b', 
                           foreground='white',
                           font=('Arial', 16, 'bold'))
        
        self.style.configure('Subtitle.TLabel',
                           background='#2b2b2b',
                           foreground='#cccccc',
                           font=('Arial', 12))
        
        self.style.configure('Green.TButton',
                           background='#28a745',
                           foreground='white',
                           font=('Arial', 10, 'bold'))
        
        self.style.configure('Red.TButton',
                           background='#dc3545',
                           foreground='white',
                           font=('Arial', 10, 'bold'))
        
        self.style.configure('Card.TFrame',
                           background='#3c3c3c',
                           relief='raised',
                           borderwidth=1)
    
    def setup_gui(self):
        # Header
        header_frame = ttk.Frame(self.root, style='Card.TFrame')
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = ttk.Label(header_frame, 
                               text="🚀 Windows Intrusion Detection System", 
                               style='Title.TLabel')
        title_label.pack(pady=10)
        
        subtitle_label = ttk.Label(header_frame,
                                  text="Real-time security monitoring with Wireshark-like network analysis",
                                  style='Subtitle.TLabel')
        subtitle_label.pack(pady=5)
        
        # Control Panel
        control_frame = ttk.Frame(self.root, style='Card.TFrame')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Status and buttons
        self.status_var = tk.StringVar(value="Status: Stopped")
        status_label = ttk.Label(control_frame, textvariable=self.status_var,
                                style='Subtitle.TLabel')
        status_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')
        
        self.start_btn = ttk.Button(control_frame, text="Start IDS",
                                   command=self.start_ids, style='Green.TButton')
        self.start_btn.grid(row=0, column=1, padx=5, pady=10)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop IDS",
                                  command=self.stop_ids, style='Red.TButton',
                                  state='disabled')
        self.stop_btn.grid(row=0, column=2, padx=5, pady=10)
        
        # Statistics
        stats_frame = ttk.Frame(control_frame, style='Card.TFrame')
        stats_frame.grid(row=0, column=3, padx=20, pady=10)
        
        self.alerts_count = 0
        self.alerts_var = tk.StringVar(value="Alerts: 0")
        alerts_label = ttk.Label(stats_frame, textvariable=self.alerts_var,
                                style='Subtitle.TLabel')
        alerts_label.pack()
        
        # Network Stats
        network_stats_frame = ttk.Frame(control_frame, style='Card.TFrame')
        network_stats_frame.grid(row=0, column=4, padx=20, pady=10)
        
        self.packets_var = tk.StringVar(value="Packets: 0")
        packets_label = ttk.Label(network_stats_frame, textvariable=self.packets_var,
                                 style='Subtitle.TLabel')
        packets_label.pack()
        
        # Clear Alerts button
        clear_btn = ttk.Button(control_frame, text="Clear Alerts",
                              command=self.clear_alerts)
        clear_btn.grid(row=0, column=5, padx=5, pady=10)
        
        # Export Network Data button
        export_btn = ttk.Button(control_frame, text="Export Network Data",
                               command=self.export_network_data)
        export_btn.grid(row=0, column=6, padx=5, pady=10)
        
        # Main content area
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Alerts tab
        alerts_tab = ttk.Frame(notebook)
        notebook.add(alerts_tab, text="🚨 Security Alerts")
        
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_tab, 
            bg='#1e1e1e', 
            fg='white',
            font=('Consolas', 10),
            wrap=tk.WORD
        )
        self.alerts_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Configure text colors
        self.alerts_text.tag_config("CRITICAL", foreground="#ff4444", font=('Consolas', 10, 'bold'))
        self.alerts_text.tag_config("WARNING", foreground="#ffaa00", font=('Consolas', 10, 'bold'))
        self.alerts_text.tag_config("INFO", foreground="#44ff44")
        
        # Dashboard tab
        dashboard_tab = ttk.Frame(notebook)
        notebook.add(dashboard_tab, text="📊 Dashboard")
        
        self.setup_dashboard(dashboard_tab)
        
        # Network Monitor tab
        network_tab = ttk.Frame(notebook)
        notebook.add(network_tab, text="🌐 Network Monitor")
        
        self.setup_network_monitor(network_tab)
        
        # Configuration tab
        config_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="⚙️ Configuration")
        
        self.setup_configuration(config_tab)
    
    def setup_network_monitor(self, parent):
        """Setup Wireshark-like network monitoring tab"""
        # Main frame
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Top control panel
        control_frame = ttk.Frame(main_frame, style='Card.TFrame')
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Control buttons
        ttk.Button(control_frame, text="🔄 Refresh Stats", 
                  command=self.refresh_network_stats).pack(side='left', padx=5)
        ttk.Button(control_frame, text="🗑️ Clear Stats", 
                  command=self.clear_network_stats).pack(side='left', padx=5)
        ttk.Button(control_frame, text="💾 Export Data", 
                  command=self.export_network_data).pack(side='left', padx=5)
        
        # Status indicators
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(side='right', padx=10)
        
        self.network_status_var = tk.StringVar(value="🔴 Network: Inactive")
        ttk.Label(status_frame, textvariable=self.network_status_var, 
                 style='Subtitle.TLabel').pack()
        
        # Main content area with notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # Overview Tab
        overview_tab = ttk.Frame(notebook)
        notebook.add(overview_tab, text="📊 Overview")
        self.setup_overview_tab(overview_tab)
        
        # Conversations Tab
        conversations_tab = ttk.Frame(notebook)
        notebook.add(conversations_tab, text="💬 Conversations")
        self.setup_conversations_tab(conversations_tab)
        
        # DNS Tab
        dns_tab = ttk.Frame(notebook)
        notebook.add(dns_tab, text="🔍 DNS")
        self.setup_dns_tab(dns_tab)
        
        # Protocols Tab
        protocols_tab = ttk.Frame(notebook)
        notebook.add(protocols_tab, text="📡 Protocols")
        self.setup_protocols_tab(protocols_tab)

    def setup_overview_tab(self, parent):
        """Setup overview tab with key statistics"""
        # Create frames for different sections
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left column - Basic stats
        left_frame = ttk.Frame(stats_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="📈 Basic Statistics", style='Title.TLabel').pack(anchor='w')
        
        self.basic_stats_text = scrolledtext.ScrolledText(
            left_frame,
            height=12,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.basic_stats_text.pack(fill='both', expand=True)
        self.basic_stats_text.config(state='disabled')
        
        # Right column - Top talkers
        right_frame = ttk.Frame(stats_frame)
        right_frame.pack(side='right', fill='both', expand=True)
        
        ttk.Label(right_frame, text="🏆 Top Talkers", style='Title.TLabel').pack(anchor='w')
        
        self.talkers_text = scrolledtext.ScrolledText(
            right_frame,
            height=12,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.talkers_text.pack(fill='both', expand=True)
        self.talkers_text.config(state='disabled')

    def setup_conversations_tab(self, parent):
        """Setup conversations tab"""
        ttk.Label(parent, text="💬 Network Conversations", style='Title.TLabel').pack(anchor='w', padx=10, pady=5)
        
        self.conv_text = scrolledtext.ScrolledText(
            parent,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.conv_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.conv_text.config(state='disabled')

    def setup_dns_tab(self, parent):
        """Setup DNS monitoring tab"""
        ttk.Label(parent, text="🔍 DNS Query History", style='Title.TLabel').pack(anchor='w', padx=10, pady=5)
        
        self.dns_text = scrolledtext.ScrolledText(
            parent,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.dns_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.dns_text.config(state='disabled')

    def setup_protocols_tab(self, parent):
        """Setup protocol statistics tab"""
        ttk.Label(parent, text="📡 Protocol Distribution", style='Title.TLabel').pack(anchor='w', padx=10, pady=5)
        
        self.protocol_text = scrolledtext.ScrolledText(
            parent,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.protocol_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.protocol_text.config(state='disabled')

    def refresh_network_stats(self):
        """Refresh all network statistics displays"""
        if self.ids and self.running:
            try:
                # Update network status
                if hasattr(self.ids, 'network_stats') and self.ids.network_stats['total_packets'] > 0:
                    self.network_status_var.set(f"🟢 Network: Active ({self.ids.network_stats['total_packets']} packets)")
                else:
                    self.network_status_var.set("🟡 Network: Monitoring...")
                
                # Get statistics from IDS
                stats = self.ids.get_network_statistics()
                self.update_network_displays(stats)
                
            except Exception as e:
                self.network_status_var.set("🔴 Network: Error")
                self.add_alert(f"INFO: Failed to refresh network stats: {e}")
        else:
            self.network_status_var.set("🔴 Network: Inactive")

    def update_network_displays(self, stats):
        """Update all network monitoring displays with real data"""
        # Update basic statistics
        self.basic_stats_text.config(state='normal')
        self.basic_stats_text.delete('1.0', 'end')
        
        basic_info = f"""=== NETWORK STATISTICS ===
Capture Duration: {stats.get('capture_duration', '0:00:00')}
Total Packets: {stats.get('total_packets', 0):,}
Active Conversations: {stats.get('active_conversations', 0)}
Total Connections: {stats.get('total_connections', 0)}
DNS Queries: {len(stats.get('recent_dns_queries', []))}

=== PROTOCOL SUMMARY ===
"""
        protocol_stats = stats.get('protocol_distribution', {})
        total_packets = max(1, stats.get('total_packets', 1))
        
        for protocol, count in protocol_stats.items():
            percentage = (count / total_packets) * 100
            basic_info += f"{protocol.upper():6}: {count:6,} packets ({percentage:5.1f}%)\n"
        
        if not protocol_stats:
            basic_info += "No protocol data yet...\n"
        
        self.basic_stats_text.insert('1.0', basic_info)
        self.basic_stats_text.config(state='disabled')
        
        # Update top talkers
        self.talkers_text.config(state='normal')
        self.talkers_text.delete('1.0', 'end')
        
        talkers_info = "=== TOP TALKERS ===\n\n"
        top_talkers = stats.get('top_talkers', [])
        
        if top_talkers:
            for i, (ip, total_traffic, data) in enumerate(top_talkers, 1):
                sent = data.get('sent', 0)
                received = data.get('received', 0)
                talkers_info += f"{i:2d}. {ip}\n"
                talkers_info += f"     Sent: {sent:,} bytes\n"
                talkers_info += f"     Received: {received:,} bytes\n"
                talkers_info += f"     Total: {total_traffic:,} bytes\n\n"
        else:
            talkers_info += "No traffic data yet...\n"
        
        self.talkers_text.insert('1.0', talkers_info)
        self.talkers_text.config(state='disabled')
        
        # Update conversations
        self.conv_text.config(state='normal')
        self.conv_text.delete('1.0', 'end')
        
        conv_info = "=== NETWORK CONVERSATIONS ===\n\n"
        conversations = stats.get('conversation_statistics', [])
        
        if conversations:
            for i, (conv_key, packets, bytes_count) in enumerate(conversations, 1):
                conv_info += f"{i:2d}. {conv_key}\n"
                conv_info += f"     Packets: {packets:,} | Bytes: {bytes_count:,}\n\n"
        else:
            conv_info += "No conversations detected yet...\n"
        
        self.conv_text.insert('1.0', conv_info)
        self.conv_text.config(state='disabled')
        
        # Update DNS queries
        self.dns_text.config(state='normal')
        self.dns_text.delete('1.0', 'end')
        
        dns_info = "=== RECENT DNS QUERIES ===\n\n"
        dns_queries = stats.get('recent_dns_queries', [])
        
        if dns_queries:
            for query in dns_queries:
                timestamp = query.get('timestamp', '')[:19].replace('T', ' ')
                src_ip = query.get('src_ip', 'Unknown')
                dns_query = query.get('query', 'Unknown')
                query_type = query.get('type', 'A')
                dns_info += f"[{timestamp}] {src_ip} -> {dns_query} (Type: {query_type})\n"
        else:
            dns_info += "No DNS queries yet...\n"
        
        self.dns_text.insert('1.0', dns_info)
        self.dns_text.config(state='disabled')
        
        # Update protocol statistics
        self.protocol_text.config(state='normal')
        self.protocol_text.delete('1.0', 'end')
        
        protocol_info = "=== PROTOCOL DISTRIBUTION ===\n\n"
        
        if protocol_stats:
            for protocol, count in protocol_stats.items():
                percentage = (count / total_packets) * 100
                # Create a simple bar chart
                bar_length = int(percentage / 5)  # Scale bar to 20 chars max
                bar = '█' * bar_length + ' ' * (20 - bar_length)
                protocol_info += f"{protocol.upper():6}: {bar} {percentage:5.1f}% ({count:,} packets)\n"
        else:
            protocol_info += "No protocol data yet...\n"
        
        self.protocol_text.insert('1.0', protocol_info)
        self.protocol_text.config(state='disabled')
    
    def clear_network_stats(self):
        """Clear network statistics displays"""
        for text_widget in [self.basic_stats_text, self.talkers_text, self.conv_text, 
                           self.dns_text, self.protocol_text]:
            text_widget.config(state='normal')
            text_widget.delete('1.0', 'end')
            text_widget.config(state='disabled')
    
    def export_network_data(self):
        """Export network capture data to JSON"""
        if self.ids and hasattr(self.ids, 'export_network_data'):
            try:
                filename = self.ids.export_network_data()
                if filename:
                    messagebox.showinfo("Export Successful", 
                                      f"Network data exported to:\n{filename}")
                    self.add_alert(f"INFO: Network data exported to {filename}")
                else:
                    messagebox.showwarning("Export Failed", 
                                         "No network data to export")
            except Exception as e:
                messagebox.showerror("Export Error", 
                                   f"Failed to export network data:\n{str(e)}")
        else:
            messagebox.showwarning("Export Failed", 
                                 "Network monitoring not active")
    
    def setup_dashboard(self, parent):
        metrics_frame = ttk.Frame(parent, style='Card.TFrame')
        metrics_frame.pack(fill='x', padx=10, pady=10)
        
        metrics_label = ttk.Label(metrics_frame, text="Real-time Monitoring Dashboard",
                                 style='Title.TLabel')
        metrics_label.pack(pady=10)
        
        # Monitoring status
        self.monitor_text = scrolledtext.ScrolledText(
            metrics_frame,
            height=15,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 9)
        )
        self.monitor_text.pack(fill='x', padx=10, pady=10)
        self.monitor_text.insert('1.0', "Monitoring will start when you click 'Start IDS'...\n\n")
        self.monitor_text.config(state='disabled')
    
    def setup_configuration(self, parent):
        config_text = """Configuration is managed via config.yaml file.

Edit the config.yaml file to modify:
- Monitored directories
- Suspicious processes
- Network monitoring settings
- Alert thresholds
- Email notifications

The system will automatically reload configuration when changes are detected."""
        
        config_display = scrolledtext.ScrolledText(
            parent,
            bg='#1e1e1e',
            fg='white',
            font=('Consolas', 10)
        )
        config_display.pack(fill='both', expand=True, padx=10, pady=10)
        config_display.insert('1.0', config_text)
        config_display.config(state='disabled')
    
    def start_ids(self):
        try:
            self.ids = WindowsIDS()
            self.running = True
            
            # Add our custom log handler to the IDS logger
            ids_logger = logging.getLogger('WindowsIDS')
            ids_logger.addHandler(self.gui_log_handler)
            ids_logger.setLevel(logging.INFO)
            
            # Start IDS in separate thread
            ids_thread = threading.Thread(target=self.run_ids)
            ids_thread.daemon = True
            ids_thread.start()
            
            self.status_var.set("Status: Running")
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            
            # Start monitoring update
            self.update_monitoring_display()
            
            self.add_alert("INFO: IDS started successfully")
            messagebox.showinfo("Success", "IDS started successfully!\nAlerts will appear in real-time.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start IDS: {str(e)}")
    
    def run_ids(self):
        """Run the IDS in a separate thread"""
        try:
            self.ids.start()
        except Exception as e:
            self.alert_queue.put(f"CRITICAL: IDS Error: {str(e)}")
    
    def stop_ids(self):
        if self.ids:
            # Remove our log handler
            ids_logger = logging.getLogger('WindowsIDS')
            ids_logger.removeHandler(self.gui_log_handler)
            
            self.ids.stop()
        self.running = False
        self.status_var.set("Status: Stopped")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.add_alert("INFO: IDS stopped")
        messagebox.showinfo("Info", "IDS stopped")
    
    def add_alert(self, alert_data):
        """Add alert to the GUI display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alerts_count += 1
        self.alerts_var.set(f"Alerts: {self.alerts_count}")
        
        self.alerts_text.config(state='normal')
        
        # Extract alert level and message
        if "CRITICAL:" in alert_data:
            level = "CRITICAL"
            message = alert_data.replace("CRITICAL:", "").strip()
            emoji = "🔴"
        elif "WARNING:" in alert_data:
            level = "WARNING"
            message = alert_data.replace("WARNING:", "").strip()
            emoji = "🟡"
        else:
            level = "INFO"
            message = alert_data.replace("INFO:", "").strip()
            emoji = "🔵"
        
        # Format the alert
        formatted_alert = f"{emoji} [{timestamp}] {message}\n"
        
        # Insert with appropriate coloring
        self.alerts_text.insert('end', formatted_alert, level)
        self.alerts_text.see('end')
        self.alerts_text.config(state='disabled')
    
    def clear_alerts(self):
        """Clear all alerts from the display"""
        self.alerts_text.config(state='normal')
        self.alerts_text.delete('1.0', 'end')
        self.alerts_text.config(state='disabled')
        self.alerts_count = 0
        self.alerts_var.set("Alerts: 0")
    
    def process_alerts(self):
        """Process alerts from the queue"""
        try:
            while True:
                alert = self.alert_queue.get_nowait()
                self.add_alert(alert)
        except queue.Empty:
            pass
        finally:
            # Check for new alerts every 100ms
            self.root.after(100, self.process_alerts)
    
    def update_network_stats(self):
        """Update network statistics in real-time"""
        if self.running and self.ids:
            try:
                # Update packet counter in header
                if hasattr(self.ids, 'network_stats'):
                    packets = self.ids.network_stats.get('total_packets', 0)
                    self.packets_var.set(f"Packets: {packets:,}")
                    
                    # Auto-refresh network displays when we have data
                    if packets > 0:
                        self.refresh_network_stats()
                        
            except Exception as e:
                pass
        
        # Continue updating every 3 seconds
        self.root.after(3000, self.update_network_stats)
    
    def update_monitoring_display(self):
        if self.running and self.ids:
            try:
                current_time = datetime.now().strftime("%H:%M:%S")
                self.monitor_text.config(state='normal')
                self.monitor_text.delete('1.0', 'end')
                
                # Get network stats safely
                network_stats = getattr(self.ids, 'network_stats', {})
                packet_count = network_stats.get('total_packets', 0)
                conversations = network_stats.get('conversations', {})
                
                monitoring_info = f"""=== System Monitoring ===
Last Update: {current_time}
Alerts Triggered: {self.alerts_count}
Status: {'Active' if self.running else 'Stopped'}

Modules Running:
{'✓' if self.ids.config['fim']['enabled'] else '✗'} File Integrity Monitoring
{'✓' if self.ids.config['process_monitor']['enabled'] else '✗'} Process Monitoring  
{'✓' if self.ids.config['network_monitor']['enabled'] else '✗'} Network Monitoring
{'✓' if self.ids.config['event_log_monitor']['enabled'] else '✗'} Event Log Monitoring

Network Statistics:
Packets Captured: {packet_count:,}
Active Conversations: {len(conversations)}

Recent Activity:
- Monitoring {len(self.ids.baseline_hashes) if hasattr(self.ids, 'baseline_hashes') else 0} files
- System time: {current_time}
"""
                self.monitor_text.insert('1.0', monitoring_info)
                self.monitor_text.config(state='disabled')
            except Exception as e:
                print(f"Monitoring update error: {e}")
        
        if self.running:
            self.root.after(2000, self.update_monitoring_display)

def main():
    root = tk.Tk()
    app = IDSGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()