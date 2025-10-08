🛡️ Windows Intrusion Detection System (Windows IDS)
A comprehensive, real-time intrusion detection system for Windows with a modern GUI interface. Monitor file integrity, processes, network activity, and Windows event logs for security threats.

https://img.shields.io/badge/Platform-Windows-blue
https://img.shields.io/badge/Python-3.8%252B-green
https://img.shields.io/badge/License-MIT-yellow

✨ Features
🔍 File Integrity Monitoring - Real-time file change detection with SHA-256 hashing

🖥️ Process Monitoring - Detection of suspicious processes and executables

🌐 Network Monitoring - Packet inspection and suspicious connection detection

📊 Event Log Monitoring - Windows Security event log analysis

🎨 Modern GUI - Dark-themed intuitive interface with real-time alerts

📧 Email Alerts - Configurable email notifications for critical events

⚡ Real-time Detection - Immediate alerting for security incidents

🛠️ Configurable - YAML-based configuration for easy customization

📸 Screenshots
GUI Interface showing real-time security alerts and monitoring dashboard

📋 Prerequisites
Windows 10/11 or Windows Server 2016+

Python 3.8 or higher

Administrator privileges (for full monitoring capabilities)

🚀 Quick Start
Method 1: Automated Setup (Recommended)
Clone the repository

bash
git clone https://github.com/yourusername/windows-ids.git
cd windows-ids
Run the automated setup (PowerShell as Administrator)

powershell
.\scripts\Setup-IDS.ps1
Method 2: Manual Installation
Install Python dependencies

bash
pip install -r requirements.txt
Run the IDS

bash
# GUI Mode (Recommended)
python main.py --gui

# Console Mode
python main.py --console
📁 Project Structure
text
windows-ids/
├── src/
│   ├── main.py                 # Main application entry point
│   ├── ids_core.py            # Core IDS engine and monitoring logic
│   └── gui.py                 # Modern GUI interface
├── config/
│   └── config.yaml            # Configuration settings
├── scripts/
│   ├── Install-IDS.ps1        # PowerShell installation script
│   ├── Start-IDS.ps1          # PowerShell launcher script
│   ├── Test-IDS.ps1           # System verification script
│   └── Setup-IDS.ps1          # Complete setup script
├── docs/
│   └── images/                # Screenshots and documentation assets
├── logs/                      # Auto-created logs directory
├── requirements.txt           # Python dependencies
└── README.md                  # This file
⚙️ Configuration
Edit config/config.yaml to customize monitoring:

File Integrity Monitoring
yaml
fim:
  enabled: true
  monitor_paths:
    - C:\Windows\System32
    - C:\Program Files
  excluded_extensions:
    - .tmp
    - .log
    - .cache
Process Monitoring
yaml
process_monitor:
  enabled: true
  suspicious_processes:
    - mimikatz.exe
    - nc.exe
    - psexec.exe
    - metasploit
Email Alerts
yaml
alerts:
  email_alerts: true
  email_settings:
    smtp_server: smtp.gmail.com
    smtp_port: 587
    username: "your_email@gmail.com"
    password: "your_app_password"  # Gmail App Password
    to_email: "alerts_destination@gmail.com"
🎯 Usage
Starting the IDS
Graphical Interface (Recommended):

powershell
python src/main.py --gui
Console Mode:

powershell
python src/main.py --console
Using the GUI
Click "Start IDS" to begin monitoring

View real-time alerts in the "Security Alerts" tab

Monitor system status in the "Dashboard" tab

Configure settings in the "Configuration" tab

Click "Stop IDS" to halt monitoring

PowerShell Scripts
All scripts are located in the scripts/ directory:

Install-IDS.ps1 - Install dependencies

Start-IDS.ps1 - Launch the IDS

Test-IDS.ps1 - Verify installation

Setup-IDS.ps1 - Complete automated setup

🔧 Troubleshooting
Common Issues
"pip is not recognized"

Install Python from python.org

Check "Add Python to PATH" during installation

Permission Errors

Run PowerShell as Administrator

Allow through Windows Firewall when prompted

Module Import Errors

powershell
# Reinstall dependencies
pip install --force-reinstall psutil pywin32
Scapy Installation Issues

powershell
pip install --pre scapy[basic]
Email Setup
Gmail Configuration:

Enable 2-Factor Authentication

Generate an App Password

Use the 16-character app password in config.yaml

📊 Monitoring Capabilities
Detected Threats
✅ Unauthorized file modifications

✅ Suspicious process execution

✅ Network connections to blocked IPs

✅ Suspicious port activity

✅ Critical Windows security events

✅ New file creations in system directories

Alert Levels
🔴 CRITICAL - Immediate threats (suspicious processes, file modifications)

🟡 WARNING - Potential issues (new files, network anomalies)

🔵 INFO - Informational messages

🛡️ Security Features
Real-time baseline creation for file integrity

SHA-256 hashing for accurate file verification

Windows Event Log integration

Network packet inspection

Process tree monitoring

Configurable whitelisting/blacklisting

📝 Logging
Alerts are logged to:

Console (colored output)

logs/alerts.log file

Email (if configured)

GUI interface (real-time)

🔒 Security Notes
Requires Administrator privileges for full functionality

Monitor sensitive directories with caution

Secure your config.yaml - contains email credentials

Use App Passwords for email, not regular passwords

Test in isolated environment before production use

🤝 Contributing
We welcome contributions! Please see our Contributing Guide for details.

Fork the repository

Create a feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add some amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

🐛 Bug Reports
Found a bug? Please open an issue and include:

Windows version

Python version

Error message and stack trace

Steps to reproduce

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
This tool is for educational and security monitoring purposes. Use responsibly and in compliance with all applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this program.

🆘 Support
For issues and questions:

Check the troubleshooting section above

Verify all dependencies are installed

Ensure you're running as Administrator

Check the logs/alerts.log file for error details

Open an issue on GitHub

Happy Monitoring! 🛡️

📞 Contact
GitHub: @yourusername

Project Link: https://github.com/yourusername/windows-ids

🙏 Acknowledgments
psutil for process monitoring

Scapy for network packet manipulation

Watchdog for file system monitoring

PyYAML for configuration management

<div align="center">
If you find this project useful, please give it a ⭐!

</div>

