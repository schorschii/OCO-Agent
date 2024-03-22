# Open Computer Orchestration
**Self Hosted / On Premise Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. It provides software deployment features, a user-computer logon overview, lists software packages installed on each computer ("recognised software") and features a fine-grained permission/role system.

It focuses on easy usability (UI/UX), simplicity (assessable code with minimal external dependencies) and performance (you can manage many computers with minimal server resources).

| [OCO Server] | [OCO Server Extensions] | [OCO Agent] |
| ------------ | ----------------------- | ----------- |

[OCO Server]: https://github.com/schorschii/oco-server
[OCO Server Extensions]: https://github.com/schorschii/oco-server-extensions
[OCO Agent]: https://github.com/schorschii/oco-agent

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. This means that no additional port has to be opened - the client initiates the connection to the server. The agent can manage Linux, Windows and macOS machines.

## System Requirements
### Agent
- 🐧 official supported Linux systems (`.deb` package provided)
  - Debian 10, 11, 12
  - Ubuntu 18.04, 20.04, 21.04, 22.04
  - derived distros like Linux Mint 19, 20, 21 etc. with systemd (sysvinit is not supported by the official `.deb` package)
- 🐧 other Linux Systems will most likely work as well but may require manual agent and dependency installation
- 🍏 macOS 11, 12, 13 and 14 (`.pkg` package provided)
- 🪟 Windows 7, 8(.1), 10 and 11 (`.exe` setup provided)
  <details>
  <summary>Windows 11 hint</summary>
  
  Windows 11 Build 22000 (the first official release build) is internally still named "Windows 10" (tested with the "Education" edition). The OCO agent will work but shows "Windows 10" as operating system. This is not an agent but a Windows issue, because the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` is not updated to "Windows 11". Please use the build number to identify Windows 11 machines in the OCO web console. BTW: great job, Microsoft!
  </details>

### Server / (Admin) Client
- please refer to [OCO Server](https://github.com/schorschii/oco-server)

## Package Installation
1. Please download and install the appropriate installation package for your operating system from the [latest release](https://github.com/schorschii/oco-agent/releases) on GitHub.
2. Configure your agent using one method described in the "Agent Setup" section.

## Agent Setup
### Via Installer
The installer will ask you for all necessary configuration values during the setup. If you fill out the fields correctly, no more configuration is required.

For a fully automated installation, it is necessary to hand over the OCO server name and agent key to the setup. This can be done as follows.

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
  Then, call the setup with the parameter `/LOADINF=.\oco-agent-setup.inf /SILENT`. Delete the `oco-agent-setup.inf` file after the agent installation to protect the agent key.

### Manually
Set the URL to the server's `api-agent.php` and set correct agent key (as defined on the server's config file) manually in the agent config file `oco-agent.ini`. The agent config file can be found in the installation directory on Windows or under `/etc` on Linux. After that, restart the service.

**General Note:** If you leave the server name empty, the agent tries to query the SRV record `_oco._tcp.yourdomain.tld` on the first startup from your DNS. The agent will then use this value and save the server name in its config file.

### macOS Hostname Note
macOS uses dynamic hostnames from your DHCP server by default. This behaviour may not be desired when using OCO since the hostname is a unique identifier in the OCO server. You can disable this feature in the system settings:

1. Open System Preferences, click General -> Sharing -> Edit (Local Hostname)
2. Uncheck the "Use dynamic global hostname" checkbox and set the desired, unique hostname.
3. Open the Terminal from the Applications / Utilities folder and look at the hostname on the prompt, ensure that it is correct.

## Integration in your OS installation
You can use known techniques to integrate the agent into your "golden master" OS image. Please have a look at [OS-Installation.md](https://github.com/schorschii/OCO-Server/blob/master/docs/OS-Installation.md) in the docs of the OCO server repo for more information.

## Manual Installation
This is how you manually install the agent.

Please do not forget to adjust the config file to point to your OCO server and set the correct agent key (defined on the server's web frontend). Set appropriate permissions to only allow root/Administrator to read the file content in order to protect the agent key.

### Linux (Systemd)
```
# install available python modules globally to avoid duplicate install in venv
apt install python3-dnspython python3-requests python3-netifaces python3-psutil python3-distro python3-pip python3-dateutil python3-venv python3-systemd mokutil

# using system site packages is important for the systemd journalctl module
python3 -m venv venv --system-site-packages
venv/bin/pip3 install pyinstaller .

venv/bin/pyinstaller oco-agent.linux.spec

# copy `dist/oco-agent` to `/usr/share/oco-agent`
# copy `oco-agent.example.ini` to `/etc/oco-agent.ini` and enter your server details
# copy `oco-agent.service` to `/etc/systemd/system/oco-agent.service`

systemctl enable oco-agent
systemctl start oco-agent
```

### macOS
```
python3 -m venv venv
venv/bin/pip3 install pyinstaller .

venv/bin/pyinstaller oco-agent.macos.spec

# move compiled binary `oco-agent` to `/opt/oco-agent/oco-agent`
# copy `oco-agent.example.ini` to `/opt/oco-agent/oco-agent.ini` and enter your server details
# copy `systems.sieber.oco-agent.plist` file to `/Library/LaunchDaemons/systems.sieber.oco-agent.plist`

sudo launchctl load /Library/LaunchDaemons/systems.sieber.oco-agent.plist
sudo launchctl start /Library/LaunchDaemons/systems.sieber.oco-agent.plist
```

### Windows
```
python -m venv venv
venv\Scripts\pip3 install pyinstaller .

venv\Scripts\pyinstaller oco-agent.windows.spec

# copy `dist/oco-agent` to `C:\Program Files\OCO Agent`
# copy `oco-agent.example.ini` to `C:\Program Files\OCO Agent` and enter your server details

"C:\Program Files\OCO Agent\service-wrapper.exe" --startup auto install
"C:\Program Files\OCO Agent\service-wrapper.exe" start
```

## Troubleshooting/Debugging
In case of problems, you can debug the agent by manually executing the python script or compiled binary in a terminal.

1. Stop the OCO-Agent service if installed.
2. Open a terminal as root/Administrator and change into the agent program directory.
3. Start the `oco-agent.exe`/`./oco-agent` binary and check its output.
4. (optional) Set the `debug = 1` option in the `oco-agent.ini` file for more verbose output.

If you can't solve the problem, you can create an issue on Github. Include the output from your terminal.

## Service Monitoring
OCO offers basic monitoring features. You can check anything by writing your own service check script and placing it into the agent's local check directory (`/usr/lib/oco-agent/service-checks` on Linux; respectively `service-checks` inside the oco agent directory on Windows and macOS). Your script just have to produce standardised output in the [CheckMK check format](https://docs.checkmk.com/latest/de/localchecks.html).

Please note that your scripts are executed on every agent execution. You have to care about caching by yourself if your script has a long runtime or produces heavy CPU load.

### Example: Check If A Windows Service Is Running
```
@echo off

for /F "tokens=3 delims=: " %%H in ('sc query Sense ^| findstr "        STATE"') do (
  if /I "%%H" NEQ "RUNNING" (
   echo 2 "Windows Defender Advanced Threat Protection Service" - Service is not running!
   exit
  )
)

echo 0 "Windows Defender Advanced Threat Protection Service" - Service is running
```
