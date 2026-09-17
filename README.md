#Windows Intrusion Detection System (Windows IDS)

*Prerequisites*
Windows 10/11 or Windows Server 2016+

Python 3.8 or higher

Administrator privileges (for full monitoring capabilities)

Quick Start
Method 1: Automated Setup (Recommended)
Clone the repository

bash
git clone https://github.com/yourusername/windows-ids.git
cd windows-ids
Run the automated setup (PowerShell as Administrator)

powershell
.\scripts\Setup-IDS.ps1

Manual Installation
Install Python dependencies

bash
pip install -r requirements.txt
Run the IDS

bash
# GUI Mode (Recommended)
python main.py --gui

# Console Mode
python main.py --console

*PowerShell Scripts*

Install-IDS.ps1 - Install dependencies

Start-IDS.ps1 - Launch the IDS

Test-IDS.ps1 - Verify installation

Setup-IDS.ps1 - Complete automated setup


If you find this project useful, please give it a ⭐!

</div>

