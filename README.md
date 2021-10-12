# Open Computer Orchestration
**Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. Additionally, it provides software deployment features and a user logon overview.

- [OCO Server](https://github.com/schorschii/oco-server)
- [OCO Server Extensions](https://github.com/schorschii/oco-server-extensions)
- [OCO Agent](https://github.com/schorschii/oco-agent)

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. This means that no additional port has to be opened - the client initiates the connection to the server. The agent can manage Linux, Windows and macOS machines.

## System Requirements
### Agent
- 🐧 official supported Linux systems (`.deb` package provided)
  - Ubuntu 18.04, 20.04 and 21.04
  - derived distros like Linux Mint 19, 20 etc.
- 🐧 other Linux Systems will most likely work as well but may require manual agent and dependency installation
- 🍏 macOS 10.15 and 10.16 (`.pkg` package provided)
- 🪟 Windows 7, 8(.1), 10 and 11 (`.exe` setup provided)
  <details>
  <summary>Windows 11 hint</summary>
  
  Windows 11 Build 22000 (the first official release build) is internally still named "Windows 10" (tested with the "Education" edition). The OCO agent will work but shows "Windows 10" as operating system. This is not an agent but a Windows issue, because the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` is not updated to "Windows 11". Please use the build number to identify Windows 11 machines in the OCO web console. BTW: great job, Microsoft!
  </details>

### Server / Client
- please refer to [OCO Server](https://github.com/schorschii/oco-server)

## Package Installation
1. Please download and install the appropriate installation package for your operating system from the [latest release](https://github.com/schorschii/oco-agent/releases) on GitHub.
2. Adjust the config file (.ini) in the installation directory (respectively `/etc`) to point to your OCO server and set the correct agent key (defined on the server's web frontend). Restart the service.

## Integration in your OS installation
You can use known techniques to integrate the agent into your "golden master" OS image, e.g.:

- [Ubuntu Live CD Customization](https://help.ubuntu.com/community/LiveCDCustomization) or [Live CD remastering](https://wiki.ubuntuusers.de/LiveCD_manuell_remastern/) for Linux
- [NTLite](https://www.ntlite.com/) or [DISM](https://docs.microsoft.com/de-de/windows-hardware/manufacture/desktop/what-is-dism) for Windows

## Manual Installation
This is how you manually install the agent.

Please do not forget to adjust the config file (.ini) to point to your OCO server and set the correct agent key (defined on the server's web frontend). Set appropriate permissions to only allow root/Administrator to read the file content in order to protect the agent key.

In case of problems, you can debug the agent by manually executing the script in terminal as root/Administrator, so you can check its output.

**Hint:** You can create your own agent package which already contains the correct agent key and server address for your environment using methods described [here](https://github.com/schorschii/oco-server/blob/master/docs/Packages.md). I'm also offering the service to produce such specialized packages. Please [contact me](https://georg-sieber.de/?page=impressum) if you're interested.

### Linux (Systemd)
No compilation needed, just install all dependencies and oco-agent.service file for systemd.
```
apt install python3-requests python3-netifaces python3-urllib3 python3-psutil python3-distro python3-pip python3-dateutil mokutil
sudo -H pip3 install utmp pyedid

# move oco-agent.py to /usr/bin and make it executable
# move oco-agent.ini to /etc
# move oco-agent.service to /etc/systemd/system

systemctl enable oco-agent
systemctl start oco-agent
```

### macOS
```
pip install pyedid

pyinstaller -F oco-agent.py

# move binary to /opt/oco-agent/oco-agent
# move .ini to /opt/oco-agent/oco-agent
# move .plist file to /Library/LaunchDaemons

sudo launchctl load /Library/LaunchDaemons/systems.sieber.oco-agent.plist
sudo launchctl start /Library/LaunchDaemons/systems.sieber.oco-agent.plist
```

### Windows
```
pip install pip install requests netifaces urllib3 psutil distro python-dateutil pyedid
pip install wmi pywin32 winevt  # Windows specific modules

# since of April 2021, winevt has two bugs which prevents oco-agent from successfully parsing windows logins
# if necessary, please apply the following patches manually to winevt library before compiling the agent
# https://github.com/bannsec/winevt/pull/13/files
# https://github.com/bannsec/winevt/pull/12/files

pyinstaller -F oco-agent.py
pyinstaller -F --hidden-import=win32timezone service-wrapper.py

# move both .exe files and .ini to: C:\Program Files\OCO Agent

service-wrapper.exe --startup auto install
service-wrapper.exe start
```
