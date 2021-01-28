# Open Computer Orchestration
**Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. Additionally, it provides software deployment features and a user logon overview.

- [OCO Server](https://github.com/schorschii/oco-server)
- [OCO Agent](https://github.com/schorschii/oco-agent)

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. This means that no additional port has to be opened - the client initiates the connection to the server. The agent can manage Linux, Windows and macOS machines.

## Package Installation
1. Please visit the Github release page of this repo, download and install the appropriate installation package for your operating system.
2. Adjust the config file (.ini) in the installation directory (respectively `/etc`) to point to your OCO server and set the correct client key (defined on the server's web frontend).

## Manual Installation
0. Make sure Python 3 and all required modules are installed (use `sudo -H` for system-wide module installation).
   - Linux: `apt install python3-requests python3-netifaces python3-urllib3 python3-psutil python3-distro python3-pip python3-dateutil mokutil`
   - Windows: `pip install pip install requests netifaces urllib3 psutil distro python-dateutil`
   - only for Linux: `(sudo -H) pip3 install utmp`
   - only for Windows: `pip install wmi winapps`
   - only for macOS: `pip install plistlib`
1. Copy the agent script and config file into an appropriate program dir (e.g. `/opt/oco-agent`).
2. Adjust the config file (.ini) in the installation directory to point to your OCO server and set the correct client key (defined on the server's web frontend). Set appropriate permissions to only allow root/Administrator to read the file content in order to protect the client key.
3. Manually execute the script as root/Administrator in terminal to check its functionality.
4. Set up your system to run the agent script as service (respectively run at startup with the Windows Task Scheduler). Concrete steps depending on your init system. A `.service` file for systemd is included in this repo (move it to `/etc/systemd/system` and run `systemctl enable oco-agent && systemctl start oco-agent`).

## Integration in your OS installation
You can use known techniques to integrate the agent into your "golden master" OS image, e.g.:

- [Ubuntu Live CD Customization](https://help.ubuntu.com/community/LiveCDCustomization) or [Live CD remastering](https://wiki.ubuntuusers.de/LiveCD_manuell_remastern/) for Linux
- [NTLite](https://www.ntlite.com/) or [DISM](https://docs.microsoft.com/de-de/windows-hardware/manufacture/desktop/what-is-dism) for Windows

## Development
### Build Process
```
# LINUX
# no compilation needed, just install oco-agent.service file for systemd
# move oco-agent.service to /etc/systemd/system
systemctl enable oco-agent
systemctl start oco-agent

# WINDOWS
pyinstaller -F --icon=assets\icons\app.ico oco-agent.py
pyinstaller -F --hidden-import=win32timezone service-wrapper.py
# move both to: C:\Program Files\OCO Agent
service-wrapper.exe install
service-wrapper.exe start
# then enable service autostart in windows control panel

# MACOS
# coming soon...
```
