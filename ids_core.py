# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 13:59:18 2025

@author: shook
"""
import os
import hashlib
import time
import threading
import psutil
import win32evtlog
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import logging
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, deque
import json
import socket

class WindowsIDS:
    def __init__(self, config_path="config.yaml"):
        self.load_config(config_path)
        self.setup_logging()
        self.baseline_hashes = {}
        self.running = False
        self.threads = []
        
        # Wireshark-like network monitoring
        self.network_stats = {
            'total_packets': 0,
            'start_time': datetime.now(),
            'connections': defaultdict(list),
            'conversations': defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None}),
            'dns_queries': deque(maxlen=1000),
            'port_scan_attempts': defaultdict(lambda: {'ports': set(), 'start_time': None}),
            'protocol_stats': defaultdict(int),
            'top_talkers': defaultdict(lambda: {'sent': 0, 'received': 0})
        }
        
    def load_config(self, config_path):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)['ids_config']
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['alerts']['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('WindowsIDS')
    
    def alert(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] {level}: {message}"
        
        # Console alert (GUI-like format)
        if self.config['alerts']['console_alerts']:
            emoji = "🔴" if level == "CRITICAL" else "🟡" if level == "WARNING" else "🔵"
            print(f"{emoji} {alert_msg}")
        
        # Log file
        self.logger.log(
            getattr(logging, level.upper(), logging.INFO),
            message
        )
        
        # Email alert (if configured)
        if (self.config['alerts']['email_alerts'] and 
            level in ["CRITICAL"]):
            try:
                # Create formatted message for email
                email_message = f"{level}: {message}"
                self.send_email_alert(email_message)
            except Exception as e:
                self.logger.error(f"Failed to send email alert: {e}")
    
    def send_email_alert(self, message):
        try:
            email_config = self.config['alerts']['email_settings']
            
            # Parse the alert message to extract level and content
            if "CRITICAL:" in message:
                level = "CRITICAL"
                emoji = "🔴"
                alert_content = message.split("CRITICAL:", 1)[1].strip()
            elif "WARNING:" in message:
                level = "WARNING" 
                emoji = "🟡"
                alert_content = message.split("WARNING:", 1)[1].strip()
            else:
                level = "INFO"
                emoji = "🔵"
                alert_content = message
            
            # Clean up event log messages
            if "Critical Event Log:" in alert_content:
                # Format event log messages better
                alert_content = self.format_event_log_message(alert_content)
            
            # Create HTML email with GUI-like formatting
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: 'Consolas', 'Monaco', monospace;
                        background-color: #1e1e1e;
                        color: #ffffff;
                        padding: 20px;
                    }}
                    .alert-container {{
                        background-color: #2b2b2b;
                        border-left: 5px solid {'#ff4444' if level == 'CRITICAL' else '#ffaa00'};
                        padding: 15px;
                        margin: 10px 0;
                        border-radius: 5px;
                    }}
                    .alert-header {{
                        font-size: 16px;
                        font-weight: bold;
                        margin-bottom: 8px;
                    }}
                    .alert-time {{
                        color: #cccccc;
                        font-size: 12px;
                    }}
                    .alert-content {{
                        color: #ffffff;
                        white-space: pre-wrap;
                        font-family: 'Consolas', monospace;
                    }}
                    .critical {{
                        color: #ff4444;
                    }}
                    .warning {{
                        color: #ffaa00;
                    }}
                    .info {{
                        color: #44ff44;
                    }}
                </style>
            </head>
            <body>
                <div class="alert-container">
                    <div class="alert-header">
                        {emoji} <span class="{level.lower()}">Windows IDS {level} Alert</span>
                    </div>
                    <div class="alert-time">
                        {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    </div>
                    <div class="alert-content">
                        {alert_content}
                    </div>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background-color: #3c3c3c; border-radius: 5px;">
                    <strong>📊 System Status:</strong><br>
                    • File Integrity Monitoring: {'✅ Active' if self.config['fim']['enabled'] else '❌ Inactive'}<br>
                    • Process Monitoring: {'✅ Active' if self.config['process_monitor']['enabled'] else '❌ Inactive'}<br>
                    • Network Monitoring: {'✅ Active' if self.config['network_monitor']['enabled'] else '❌ Inactive'}<br>
                    • Event Log Monitoring: {'✅ Active' if self.config['event_log_monitor']['enabled'] else '❌ Inactive'}<br>
                    <br>
                    <em>This alert was generated automatically by Windows IDS</em>
                </div>
            </body>
            </html>
            """
            
            # Create plain text version as fallback
            text_content = f"""
            🚨 WINDOWS IDS {level} ALERT
            {'='*50}
            Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            Level: {level} {emoji}
            
            Alert: {alert_content}
            
            System Status:
            • File Integrity Monitoring: {'Active' if self.config['fim']['enabled'] else 'Inactive'}
            • Process Monitoring: {'Active' if self.config['process_monitor']['enabled'] else 'Inactive'} 
            • Network Monitoring: {'Active' if self.config['network_monitor']['enabled'] else 'Inactive'}
            • Event Log Monitoring: {'Active' if self.config['event_log_monitor']['enabled'] else 'Inactive'}
            
            ---
            Automated alert from Windows Intrusion Detection System
            """
            
            # Create MIME message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f'🚨 Windows IDS {level} Alert - {datetime.now().strftime("%H:%M:%S")}'
            msg['From'] = email_config['username']
            msg['To'] = email_config['to_email']
            
            # Attach both HTML and plain text versions
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"📧 {level} email alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def format_event_log_message(self, message):
        """Format Windows Event Log messages for better readability"""
        if "Critical Event Log:" in message:
            try:
                # Extract the main parts
                parts = message.split(" - ")
                if len(parts) > 1:
                    event_info = parts[0].replace("Critical Event Log:", "").strip()
                    event_data = parts[1]
                    
                    # Clean up the privilege list format
                    if "SeAssignPrimaryTokenPrivilege" in event_data:
                        event_data = event_data.replace("\\r\\n\\t\\t\\t", "\n                    ")
                        event_data = event_data.replace("'", "")
                    
                    formatted_message = f"""Event: {event_info}

    Details:
    {event_data}"""
                    return formatted_message
            except Exception as e:
                self.logger.debug(f"Could not format event log message: {e}")
        
        return message
    
    # Enhanced Network Monitoring with Wireshark-like features
    def packet_handler(self, packet):
        if IP in packet:
            self.network_stats['total_packets'] += 1
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_size = len(packet)
            timestamp = datetime.now()
            
            # Update protocol statistics
            if TCP in packet:
                protocol = "TCP"
                self.network_stats['protocol_stats']['tcp'] += 1
            elif UDP in packet:
                protocol = "UDP" 
                self.network_stats['protocol_stats']['udp'] += 1
            elif ICMP in packet:
                protocol = "ICMP"
                self.network_stats['protocol_stats']['icmp'] += 1
            else:
                protocol = "Other"
                self.network_stats['protocol_stats']['other'] += 1
            
            # Track conversations (like Wireshark's Conversations window)
            conv_key = f"{ip_src} <-> {ip_dst}"
            self.network_stats['conversations'][conv_key]['packets'] += 1
            self.network_stats['conversations'][conv_key]['bytes'] += packet_size
            self.network_stats['conversations'][conv_key]['last_seen'] = timestamp
            
            # Track top talkers
            self.network_stats['top_talkers'][ip_src]['sent'] += packet_size
            self.network_stats['top_talkers'][ip_dst]['received'] += packet_size
            
            # TCP Analysis
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Track TCP connections
                conn_key = f"{ip_src}:{src_port} -> {ip_dst}:{dst_port}"
                connection_info = {
                    'timestamp': timestamp.isoformat(),
                    'flags': self.get_tcp_flags(packet[TCP].flags),
                    'seq': packet[TCP].seq,
                    'ack': packet[TCP].ack,
                    'size': packet_size
                }
                self.network_stats['connections'][conn_key].append(connection_info)
                
                # Keep only last 50 connections per endpoint
                if len(self.network_stats['connections'][conn_key]) > 50:
                    self.network_stats['connections'][conn_key].pop(0)
                
                # Detect port scanning
                self.detect_port_scan(ip_src, dst_port, timestamp)
                
                # Detect SYN floods
                self.detect_syn_flood(ip_src, timestamp)
            
            # DNS Analysis
            if DNS in packet and packet[DNS].qr == 0:  # DNS Query
                try:
                    dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    dns_type = packet[DNSQR].qtype
                    
                    dns_record = {
                        'timestamp': timestamp.isoformat(),
                        'src_ip': ip_src,
                        'query': dns_query,
                        'type': dns_type,
                        'protocol': 'DNS'
                    }
                    self.network_stats['dns_queries'].append(dns_record)
                    
                    # Alert on suspicious DNS queries
                    self.check_suspicious_dns(dns_query, ip_src)
                    
                except Exception as e:
                    self.logger.debug(f"DNS parsing error: {e}")
            
            # HTTP Analysis
            if TCP in packet and (dst_port == 80 or dst_port == 443):
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if any(method in payload for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                            # Extract Host header
                            host_line = [line for line in payload.split('\r\n') if line.startswith('Host:')]
                            if host_line:
                                host = host_line[0].split('Host:')[1].strip()
                                http_info = {
                                    'timestamp': timestamp.isoformat(),
                                    'src_ip': ip_src,
                                    'host': host,
                                    'method': 'GET' if 'GET' in payload else 'POST' if 'POST' in payload else 'OTHER'
                                }
                                # Store HTTP info (you could add this to a separate deque)
                    except:
                        pass
            
            # Check blocked IPs
            if ip_src in self.config['network_monitor']['blocked_ips']:
                self.alert(f"Communication with blocked IP: {ip_src} -> {ip_dst} ({protocol})", "CRITICAL")
            
            # Check suspicious ports
            if TCP in packet:
                port = packet[TCP].dport
                if port in self.config['network_monitor']['suspicious_ports']:
                    self.alert(f"Suspicious connection to port {port} from {ip_src}", "WARNING")
            
            # Large packet detection
            if packet_size > self.config['network_monitor'].get('large_packet_threshold', 1500):
                self.alert(f"Large packet detected: {packet_size} bytes from {ip_src} -> {ip_dst}", "WARNING")
    
    def get_tcp_flags(self, flags):
        """Convert TCP flags to human-readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        return '|'.join(flag_names) if flag_names else "None"
    
    def detect_port_scan(self, src_ip, dst_port, timestamp):
        """Detect port scanning activity"""
        scan_key = src_ip
        tracker = self.network_stats['port_scan_attempts'][scan_key]
        
        if tracker['start_time'] is None:
            tracker['start_time'] = timestamp
        
        tracker['ports'].add(dst_port)
        
        # Check if we have multiple ports in short time
        time_diff = (timestamp - tracker['start_time']).total_seconds()
        port_count = len(tracker['ports'])
        
        # Alert thresholds
        if port_count >= 20 and time_diff < 10:
            self.alert(f"Rapid port scan detected from {src_ip}: {port_count} ports in {time_diff:.1f}s", "CRITICAL")
            # Reset tracker
            self.network_stats['port_scan_attempts'][scan_key] = {'ports': set(), 'start_time': None}
        elif port_count >= 10 and time_diff < 30:
            self.alert(f"Port scan detected from {src_ip}: {port_count} ports in {time_diff:.1f}s", "WARNING")
    
    def detect_syn_flood(self, src_ip, timestamp):
        """Detect SYN flood attacks"""
        # This is a simplified version - in production you'd want more sophisticated detection
        syn_count = 0
        for conn_key, connections in self.network_stats['connections'].items():
            if src_ip in conn_key:
                # Count SYN packets in last 10 seconds
                recent_syns = [c for c in connections[-10:] 
                              if 'SYN' in c['flags'] and 
                              (timestamp - datetime.fromisoformat(c['timestamp'])).total_seconds() < 10]
                syn_count += len(recent_syns)
        
        if syn_count > 50:  # Threshold for SYN flood
            self.alert(f"Possible SYN flood from {src_ip}: {syn_count} SYN packets in 10s", "CRITICAL")
    
    def check_suspicious_dns(self, query, src_ip):
        """Check for suspicious DNS queries"""
        suspicious_domains = [
            'pastebin.com', 'transfer.sh', 'file.io',  # File sharing
            'ngrok.io', 'serveo.net', 'localhost.run',  # Tunneling services
            'myexternalip.com', 'icanhazip.com',       # IP detection
        ]
        
        for domain in suspicious_domains:
            if domain in query:
                self.alert(f"Suspicious DNS query: {query} from {src_ip}", "WARNING")
                break
    
    def get_network_statistics(self):
        """Get comprehensive network statistics for GUI"""
        if not hasattr(self, 'network_stats'):
            return {
                'total_packets': 0,
                'capture_duration': '0:00:00',
                'protocol_distribution': {},
                'active_conversations': 0,
                'total_connections': 0,
                'recent_dns_queries': [],
                'top_talkers': [],
                'conversation_statistics': []
            }
        
        uptime = datetime.now() - self.network_stats['start_time']
        
        # Convert conversations to list for GUI
        conversation_stats = []
        for conv_key, data in self.network_stats['conversations'].items():
            conversation_stats.append((conv_key, data['packets'], data['bytes']))
        
        # Sort by packet count
        conversation_stats.sort(key=lambda x: x[1], reverse=True)
        
        # Get top talkers
        top_talkers = self.get_top_talkers(10)
        
        stats = {
            'capture_duration': str(uptime).split('.')[0],  # Remove microseconds
            'total_packets': self.network_stats['total_packets'],
            'protocol_distribution': dict(self.network_stats['protocol_stats']),
            'active_conversations': len(self.network_stats['conversations']),
            'total_connections': len(self.network_stats['connections']),
            'recent_dns_queries': list(self.network_stats['dns_queries'])[-20:],  # Last 20 queries
            'top_talkers': top_talkers,
            'conversation_statistics': conversation_stats[:20]  # Top 20 conversations
        }
        return stats

    def get_top_talkers(self, count=10):
        """Get top N IP addresses by traffic volume"""
        if not hasattr(self, 'network_stats'):
            return []
        
        talkers = []
        for ip, data in self.network_stats['top_talkers'].items():
            total_traffic = data['sent'] + data['received']
            talkers.append((ip, total_traffic, data))
        
        talkers.sort(key=lambda x: x[1], reverse=True)
        return talkers[:count]
    
    def get_conversation_stats(self, count=10):
        """Get top conversations by packet count"""
        conversations = []
        for conv_key, data in self.network_stats['conversations'].items():
            conversations.append((conv_key, data['packets'], data['bytes']))
        
        conversations.sort(key=lambda x: x[1], reverse=True)
        return conversations[:count]
    
    def export_network_data(self, filename=None):
        """Export captured network data to JSON file"""
        if filename is None:
            filename = f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'export_time': datetime.now().isoformat(),
            'capture_info': self.get_network_statistics(),
            'conversations': dict(self.network_stats['conversations']),
            'recent_dns_queries': list(self.network_stats['dns_queries']),
            'protocol_stats': dict(self.network_stats['protocol_stats'])
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            self.logger.info(f"Network data exported to {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Failed to export network data: {e}")
            return None
    
    def monitor_network(self):
        if not self.config['network_monitor']['enabled']:
            return
        
        self.logger.info("Starting Wireshark-like network monitoring...")
        
        try:
            # Start packet capture
            sniff(prn=self.packet_handler, store=0)
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
            # Restart network monitoring if it fails
            if self.running:
                self.logger.info("Restarting network monitoring in 10 seconds...")
                time.sleep(10)
                self.monitor_network()
    
    # File Integrity Monitoring
    def calculate_hash(self, filepath):
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return None
    
    def create_baseline(self):
        self.logger.info("Creating file integrity baseline...")
        for path in self.config['fim']['monitor_paths']:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        if any(filepath.endswith(ext) for ext in self.config['fim']['excluded_extensions']):
                            continue
                        file_hash = self.calculate_hash(filepath)
                        if file_hash:
                            self.baseline_hashes[filepath] = file_hash
        self.logger.info(f"Baseline created for {len(self.baseline_hashes)} files")
    
    class FileChangeHandler(FileSystemEventHandler):
        def __init__(self, ids_instance):
            self.ids = ids_instance
        
        def on_modified(self, event):
            if not event.is_directory:
                self.ids.check_file_integrity(event.src_path)
        
        def on_created(self, event):
            if not event.is_directory:
                self.ids.alert(f"New file created: {event.src_path}", "WARNING")
        
        def on_deleted(self, event):
            if not event.is_directory:
                self.ids.alert(f"File deleted: {event.src_path}", "WARNING")
    
    def check_file_integrity(self, filepath):
        if any(filepath.endswith(ext) for ext in self.config['fim']['excluded_extensions']):
            return
        
        current_hash = self.calculate_hash(filepath)
        if not current_hash:
            return
        
        if filepath in self.baseline_hashes:
            if self.baseline_hashes[filepath] != current_hash:
                self.alert(f"File modified: {filepath}", "CRITICAL")
        else:
            self.alert(f"New file detected: {filepath}", "WARNING")
    
    def start_fim(self):
        if not self.config['fim']['enabled']:
            return
        
        self.create_baseline()
        event_handler = self.FileChangeHandler(self)
        self.observer = Observer()
        
        for path in self.config['fim']['monitor_paths']:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=True)
        
        self.observer.start()
        self.logger.info("File Integrity Monitoring started")
    
    # Process Monitoring
    def check_suspicious_processes(self):
        suspicious_procs = self.config['process_monitor']['suspicious_processes']
        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_procs:
                    if suspicious.lower() in proc_name:
                        self.alert(f"Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})", "CRITICAL")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    
    def monitor_processes(self):
        while self.running:
            self.check_suspicious_processes()
            time.sleep(self.config['process_monitor']['check_interval'])
    
    # Event Log Monitoring
    def monitor_event_logs(self):
        if not self.config['event_log_monitor']['enabled']:
            return
            
        critical_events = [str(e) for e in self.config['event_log_monitor']['critical_events']]
        
        while self.running:
            try:
                hand = win32evtlog.OpenEventLog(None, "Security")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    if str(event.EventID) in critical_events:
                        self.alert(f"Critical Event Log: ID {event.EventID} - {event.StringInserts}", "WARNING")
                
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                self.logger.error(f"Event log monitoring error: {e}")
            
            time.sleep(10)
    
    # Main control methods
    def start(self):
        self.running = True
        self.logger.info("Starting Windows IDS...")
        
        # Start FIM
        self.start_fim()
        
        # Start process monitoring thread
        if self.config['process_monitor']['enabled']:
            process_thread = threading.Thread(target=self.monitor_processes)
            process_thread.daemon = True
            process_thread.start()
            self.threads.append(process_thread)
        
        # Start network monitoring thread
        if self.config['network_monitor']['enabled']:
            network_thread = threading.Thread(target=self.monitor_network)
            network_thread.daemon = True
            network_thread.start()
            self.threads.append(network_thread)
        
        # Start event log monitoring thread
        if self.config['event_log_monitor']['enabled']:
            event_thread = threading.Thread(target=self.monitor_event_logs)
            event_thread.daemon = True
            event_thread.start()
            self.threads.append(event_thread)
        
        self.logger.info("Windows IDS started successfully")
    
    def stop(self):
        """Stop all monitoring threads and cleanup"""
        self.running = False
        self.logger.info("Stopping Windows IDS...")
        
        # Stop File Integrity Monitoring
        if hasattr(self, 'observer'):
            try:
                self.observer.stop()
                self.observer.join(timeout=10)
                self.logger.info("File Integrity Monitoring stopped")
            except Exception as e:
                self.logger.error(f"Error stopping file monitoring: {e}")
        
        # Stop all monitoring threads
        for thread in self.threads:
            try:
                thread.join(timeout=5)
            except Exception as e:
                self.logger.debug(f"Thread join error: {e}")
        
        # Clear network statistics
        if hasattr(self, 'network_stats'):
            try:
                # Export final network data before clearing
                if self.network_stats['total_packets'] > 0:
                    self.export_network_data("network_capture_final.json")
                
                # Reset network stats
                self.network_stats['total_packets'] = 0
                self.network_stats['connections'].clear()
                self.network_stats['conversations'].clear()
                self.network_stats['dns_queries'].clear()
                self.network_stats['protocol_stats'].clear()
                self.network_stats['top_talkers'].clear()
                self.network_stats['port_scan_attempts'].clear()
                self.logger.info("Network statistics cleared")
                
            except Exception as e:
                self.logger.error(f"Error clearing network stats: {e}")
        
        # Clear baseline hashes
        self.baseline_hashes.clear()
        
        self.logger.info("Windows IDS stopped successfully")