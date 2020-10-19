# Open Computer Orchestration
**Desktop and Server Inventory, Management & Software Deployment**

The Open Computer Orchestration (OCO) project enables IT administrators to centrally manage Linux, macOS and Windows machines using a comfortable web interface. Additionally, it provides software deployment features and a user logon overview.

## About OCO Agent
The OCO agent needs to be installed on every client which should be managed with the OCO server. It periodically contacts the server to sync the inventory data and execute pending software jobs. The agent can manage Linux, Windows and macOS machines.

## Package Installation
1. Please visit the Github release page of this repo, download and install the appropriate installation package for your operating system.
2. Adjust the config file (.ini) in the installation directory to point to your OCO server.

## Manual Installation
0. Make sure Python 3 and all required modules are installed.
1. Copy the agent script and config file into a appropriate program dir (e.g. `/opt/oco-agent`).
2. Set up a cron job executing the script every minute.

## Development
### Build Process
```
# Linux/macOS
pyinstaller -F --icon=assets/icons/app.icns oco-agent.py

# Windows
pyinstaller -F --icon=assets\icons\app.ico oco-agent.py
```
