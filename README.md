# Open Computer Orchestration
**Self Hosted / On Premise Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. Additionally, it provides software deployment features, a user-computer logon overview, lists software packages installed on all computers ("recognised software") and features a fine-grained permission/role system.

It focuses on easy usability (good GUI/UX), simplicity (assessable code with minimal external dependencies) and performance (you can manage many computers with minimal server resources).

- [OCO Server](https://github.com/schorschii/oco-server)
- [OCO Server Extensions](https://github.com/schorschii/oco-server-extensions)
- [OCO Agent](https://github.com/schorschii/oco-agent)

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. This means that no additional port has to be opened - the client initiates the connection to the server. The agent can manage Linux, Windows and macOS machines.

## System Requirements
### Agent
- 🐧 official supported Linux systems (`.deb` package provided)
  - Ubuntu 18.04, 20.04, 21.04, 22.04
  - derived distros like Linux Mint 19, 20, 21 etc.
- 🐧 other Linux Systems will most likely work as well but may require manual agent and dependency installation
- 🍏 macOS 10.15, 11 and 12 (`.pkg` package provided)
- 🪟 Windows 7, 8(.1), 10 and 11 (`.exe` setup provided)
  <details>
  <summary>Windows 11 hint</summary>
  
  Windows 11 Build 22000 (the first official release build) is internally still named "Windows 10" (tested with the "Education" edition). The OCO agent will work but shows "Windows 10" as operating system. This is not an agent but a Windows issue, because the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` is not updated to "Windows 11". Please use the build number to identify Windows 11 machines in the OCO web console. BTW: great job, Microsoft!
  </details>

### Server / (Admin) Client
- please refer to [OCO Server](https://github.com/schorschii/oco-server)

## Package Installation
1. Please download and install the appropriate installation package for your operating system from the [latest release](https://github.com/schorschii/oco-agent/releases) on GitHub.
2. Adjust the config file (.ini) in the installation directory (respectively `/etc`) to point to your OCO server and set the correct agent key (defined on the server's configuration file). Restart the service.

## Agent Setup
### Via Installer
For an automated installation, it is necessary to hand over the OCO server name and agent key to the setup. This can be done as follows.

- **Debian/Ubuntu Linux**
  Preseed the debconf values for the debian package:
  ```
  echo "oco-agent oco-agent/server-name string oco.example.com" | sudo debconf-set-selections
  echo "oco-agent oco-agent/agent-key string 12345678" | sudo debconf-set-selections
  ```
  Now you can install the package normally (`apt install oco-agent.deb`). Remove the debconf values afterwards to protect the agent key.
  ```
  echo "oco-agent oco-agent/server-name string " | sudo debconf-set-selections
  echo "oco-agent oco-agent/agent-key string " | sudo debconf-set-selections
  ```

- **Windows**
  Create an InnoSetup configuration file `oco-agent-setup.inf` in the same directory with the installer `.exe`:
  ```
  [Setup]
  ServerName=oco.example.com
  AgentKey=1235678
  ```
  Then, call the setup with the parameter `/LOADINF=oco-agent-setup.inf /SILENT`. Delete the `oco-agent-setup.inf` file after the agent installation to protect the agent key.

### Manually
Set the URL to the server's `api-agent.php` manually in the agent config file `oco-agent.ini` (can be found in the installation directory on Windows or under `/etc` on Linux).

**General Note:** If you leave the server name empty, the agent tries to query the SRV record `_oco._tcp.yourdomain.tld` on the first startup from your DNS. The agent will then use this value and save the server name in its config file.

## Integration in your OS installation
You can use known techniques to integrate the agent into your "golden master" OS image. Please have a look at [OS-Installation.md](https://github.com/schorschii/OCO-Server/blob/master/docs/OS-Installation.md) in the docs of the OCO server repo for more information.

## Manual Installation
This is how you manually install the agent.

Please do not forget to adjust the config file (.ini) to point to your OCO server and set the correct agent key (defined on the server's web frontend). Set appropriate permissions to only allow root/Administrator to read the file content in order to protect the agent key.

### Linux (Systemd)
No compilation needed, just install all dependencies and oco-agent.service file for systemd.
```
apt install python3-dnspython python3-requests python3-netifaces python3-psutil python3-distro python3-pip python3-dateutil mokutil
sudo -H pip3 install pyedid  # pyedid is not available in Ubuntu/Debian repos
sudo -H pip3 install utmp  # Linux specific modules

# copy `oco-agent.py` to `/usr/bin/oco-agent` and make it executable
# copy `oco-agent.example.ini` to `/etc/oco-agent.ini` and enter your server details
# copy `oco-agent.service` to `/etc/systemd/system/oco-agent.service`

systemctl enable oco-agent
systemctl start oco-agent
```

### macOS
```
pip install dnspython requests netifaces psutil distro python-dateutil pyedid

pyinstaller -F oco-agent.py

# move compiled binary `oco-agent` to `/opt/oco-agent/oco-agent`
# copy `oco-agent.example.ini` to `/opt/oco-agent/oco-agent.ini` and enter your server details
# copy `systems.sieber.oco-agent.plist` file to `/Library/LaunchDaemons/systems.sieber.oco-agent.plist`

sudo launchctl load /Library/LaunchDaemons/systems.sieber.oco-agent.plist
sudo launchctl start /Library/LaunchDaemons/systems.sieber.oco-agent.plist
```

### Windows
```
pip install dnspython requests netifaces psutil distro python-dateutil pyedid
pip install wmi pywin32 winevt  # Windows specific modules

# since of April 2021, winevt has two bugs which prevents oco-agent from successfully parsing windows logins
# if necessary, please apply the following patches manually to winevt library before compiling the agent
# https://github.com/bannsec/winevt/pull/13/files
# https://github.com/bannsec/winevt/pull/12/files

pyinstaller -F --icon=assets/logo.ico oco-agent.py
pyinstaller -F --hidden-import=win32timezone --icon=assets/logo-service.ico service-wrapper.py

# move compiled `service-wrapper.exe` files to: `C:\Program Files\OCO Agent\service-wrapper.exe`
# move compiled `oco-agent.exe` files to: `C:\Program Files\OCO Agent\oco-agent.exe`
# copy `oco-agent.example.ini` to `C:\Program Files\OCO Agent` and enter your server details

service-wrapper.exe --startup auto install
service-wrapper.exe start
```

## Debugging
In case of problems, you can debug the agent by manually executing the script or compiled binary in terminal as root/Administrator, so you can check its output. Set the `debug = 1` in the agent config file for more verbose output.
