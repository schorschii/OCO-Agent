# Open Computer Orchestration
**Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. Additionally, it provides software deployment features and a user logon overview.

- [OCO Server](https://github.com/schorschii/oco-server)
- [OCO Agent](https://github.com/schorschii/oco-agent)
- [OCO Packager](https://github.com/schorschii/oco-packager)

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. This means that no additional port has to be opened - the client initiates the connection to the server. The agent can manage Linux, Windows and macOS machines.

## Package Installation
1. Please visit the Github release page of this repo, download and install the appropriate installation package for your operating system.
2. Adjust the config file (.ini) in the installation directory to point to your OCO server and set the correct client key (defined on the server's web frontend).

## Manual Installation
0. Make sure Python 3 and all required modules are installed.
1. Copy the agent script and config file into an appropriate program dir (e.g. `/opt/oco-agent`).
2. Adjust the config file (.ini) in the installation directory to point to your OCO server and set the correct client key (defined on the server's web frontend). Set appropriate permissions to only allow root/Administrator to read the file content in order to protect the client key.
3. Manually execute the script as root/Administrator in terminal to check its functionality.
4. Set up a cron job executing the script as root/Administrator every minute.

## Development
### Build Process
```
# Linux/macOS
pyinstaller -F --icon=assets/icons/app.icns oco-agent.py

# Windows
pyinstaller -F --icon=assets\icons\app.ico oco-agent.py
```
