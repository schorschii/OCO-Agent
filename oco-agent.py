#!/usr/bin/python3

# ╔═════════════════════════════════════╗
# ║           ___   ____ ___            ║
# ║          / _ \ / ___/ _ \           ║
# ║         | | | | |  | | | |          ║
# ║         | |_| | |__| |_| |          ║
# ║          \___/ \____\___/           ║
# ╟─────────────────────────────────────╢
# ║ Open Computer Orchestration Project ║
# ║              OCO-AGENT              ║
# ╚═════════════════════════════════════╝

import requests
import json
import socket
import netifaces
import platform
import os, sys, stat
import urllib
import configparser
import argparse
import psutil
from psutil import virtual_memory
import distro
import datetime
from dateutil import tz
import tempfile
import subprocess
from zipfile import ZipFile


AGENT_VERSION = "0.1"
OS_TYPE = sys.platform.lower()
if "win32" in OS_TYPE:
	import wmi
	import winreg


##### FUNCTIONS #####

def getNics():
	nics = []
	for interface in netifaces.interfaces():
		if(netifaces.AF_INET in netifaces.ifaddresses(interface)):
			ineta = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
			if(ineta["addr"] == "127.0.0.1"): continue
			ineta["mac"] = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
			ineta["domain"] = socket.getfqdn()
			nics.append(ineta)
	return nics

def getOs():
	if "win32" in OS_TYPE:
		return platform.system()
	elif "linux" in OS_TYPE:
		return distro.name()
	elif "darwin" in OS_TYPE:
		return "macOS"

def getOsVersion():
	if "win32" in OS_TYPE:
		return platform.platform()
	elif "linux" in OS_TYPE:
		return distro.version()
	elif "darwin" in OS_TYPE:
		return platform.mac_ver()[0]

def getKernelVersion():
	if "win32" in OS_TYPE:
		return "-"
	elif "linux" in OS_TYPE or "darwin" in OS_TYPE:
		return platform.release()

def getMachineSerial():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.SerialNumber
	elif "linux" in OS_TYPE:
		command = "dmidecode -s system-serial-number"
	elif "darwin" in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformSerialNumber/{print $(NF-1)}'"
	return os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")

def getMachineManufacturer():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.Manufacturer
	elif "linux" in OS_TYPE:
		command = "dmidecode -s system-manufacturer"
	elif "darwin" in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/manufacturer/{print $(NF-1)}'"
	return os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")

def getMachineModel():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Computersystem(): return o.Model
	elif "linux" in OS_TYPE:
		command = "dmidecode -s system-product-name"
	elif "darwin" in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/model/{print $(NF-1)}'"
	return os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")

def getBiosVersion():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.Version
	elif "linux" in OS_TYPE:
		command = "dmidecode -s bios-version"
	elif "darwin" in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/version/{print $(NF-1)}'"
	return os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")

def getUefiOrBios():
	booted = "?"
	if "win32" in OS_TYPE:
		command = "bcdedit"
		booted = "UEFI" if "EFI" in os.popen(command).read().replace("\t","").replace(" ","") else "Legacy"
	elif "linux" in OS_TYPE:
		booted = "UEFI" if os.path.exists("/sys/firmware/efi") else "Legacy"
	elif "darwin" in OS_TYPE:
		booted = "UEFI"
	return booted

def getSecureBootEnabled():
	secureboot = "?"
	if "win32" in OS_TYPE:
		try:
			registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\CurrentControlSet\Control\SecureBoot\State", 0, winreg.KEY_READ)
			value, regtype = winreg.QueryValueEx(registry_key, "UEFISecureBootEnabled")
			winreg.CloseKey(registry_key)
			return str(value)
		except WindowsError: return "0"
	elif "linux" in OS_TYPE:
		command = "mokutil --sb-state"
		secureboot = "1" if "enabled" in os.popen(command).read().replace("\t","").replace(" ","") else "0"
	return secureboot

def getInstalledSoftware():
	software = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for p in w.Win32_InstalledWin32Program():
			app_name = str(p.Name).encode("utf8","ignore").decode()
			vendor = str(p.Vendor).encode("utf8","ignore").decode()
			software.append({
				"name": app_name,
				"version": p.Version,
				"description": vendor
			})
	elif "linux" in OS_TYPE:
		command = "apt list --installed"
		for l in os.popen(command).read().split("\n"):
			packageName = l.split("/")[0]
			if(len(l.split(" ")) > 1):
				packageVersion = l.split(" ")[1];
				if(packageName != "" and packageVersion != ""):
					software.append({
						"name": packageName,
						"version": packageVersion,
						"description": ""
					})
	elif "darwin" in OS_TYPE:
		import plistlib
		appdirname = "/Applications"
		appdir = os.fsencode(appdirname)
		for app in os.listdir(appdir):
			appname = os.fsdecode(app)
			if(not os.path.isfile(appname) and appname.endswith(".app")):
				with open(os.path.join(appdirname, appname, "Contents", "Info.plist"), "rb") as f:
					plist_data = plistlib.load(f)
					software.append({
						"name": plist_data.get("CFBundleName") or appname,
						"version": plist_data.get("CFBundleVersion") or "?",
						"description": plist_data.get("CFBundleGetInfoString") or "-"
					})
	return software

def getIsActivated():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.SoftwareLicensingProduct():
			if(o.ApplicationID == "55c92734-d682-4d71-983e-d6ec3f16059f"):
				#print(o.Name)
				#print(o.Description)
				if(o.LicenseStatus == 1): return "1"
		return "0"
	else: return "-"

def getLocale():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_OperatingSystem():
			return o.Locale
		return "?"
	else: return "-"

def getCpu():
	if "win32" in OS_TYPE:
		return platform.processor()
	elif "linux" in OS_TYPE:
		command = "cat /proc/cpuinfo | grep 'model name' | uniq"
		return os.popen(command).read().split(":", 1)[1].strip()
	elif "darwin" in OS_TYPE:
		command = "sysctl -n machdep.cpu.brand_string"
		return os.popen(command).read().strip()

def getGpu():
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_VideoController(): return o.Name
		return "?"
	elif "linux" in OS_TYPE:
		return "?"
	elif "darwin" in OS_TYPE:
		command = "system_profiler SPDisplaysDataType -json"
		jsonstring = os.popen(command).read().strip()
		jsondata = json.loads(jsonstring)
		for gpu in jsondata["SPDisplaysDataType"]:
			return gpu["sppci_model"]

def getScreens():
	screens = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Desktopmonitor():
			screens.append({
				"name": o.Name,
				"manufacturer": o.MonitorManufacturer,
				"dpi": o.PixelsPerXLogicalInch,
				"resolution": str(o.ScreenWidth)+" x "+str(o.ScreenHeight),
				"type": o.DisplayType or "-"
			})
	elif "linux" in OS_TYPE:
		command = "xrandr"
		lines = os.popen(command).read().strip().splitlines()
		for display in lines:
			value = display.split()
			if(not display.startswith(" ") and value[1] == "connected"):
				resolution = value[2]
				if(resolution == "primary"): resolution = value[3];
				screens.append({
					"name": value[0],
					"manufacturer": "", "dpi": "", "type": "",
					"resolution": resolution
				})
	elif "darwin" in OS_TYPE:
		command = "system_profiler SPDisplaysDataType -json"
		jsonstring = os.popen(command).read().strip()
		jsondata = json.loads(jsonstring)
		for gpu in jsondata["SPDisplaysDataType"]:
			for screen in gpu["spdisplays_ndrvs"]:
				screens.append({
					"name": screen["_name"],
					"manufacturer": "", "dpi": "",
					"resolution": screen["_spdisplays_pixels"].strip(),
					"type": screen["spdisplays_display_type"]
				})
	return screens

def getPrinter():
	printer = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Printer():
			printer.append({
				"name": o.Name,
				"driver": o.DriverName,
				"dpi": o.HorizontalResolution,
				"local": o.Local,
				"state": o.PrinterState,
				"status": o.PrinterStatus
			})
	return printer

def getDrives():
	drives = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_LogicalDisk():
			drives.append({
				"device": "",
				"mountpoint": o.DeviceID,
				"filesystem": o.FileSystem,
				"name": o.VolumeName,
				"size": o.Size,
				"free": o.FreeSpace,
				"serial": o.VolumeSerialNumber
			})
	return drives

def getLogins():
	users = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for u in w.Win32_NetworkLoginProfile():
			if(hasattr(u, "LastLogon") and hasattr(u, "NumberOfLogons") and u.LastLogon != None and u.NumberOfLogons != 0):
				# example timestamp: 20201011200012.000000+120
				dateObject = datetime.datetime.strptime(u.LastLogon[:-4], "%Y%m%d%H%M%S.%f")
				dateObject -= datetime.timedelta(minutes=int(u.LastLogon[-4:])) # subtract to get UTC time
				users.append({
					"username": u.Caption, # u.Name -> with domain
					"console": u.NumberOfLogons,
					"timestamp": dateObject.strftime("%Y-%m-%d %H:%M:%S")
				})
	elif "linux" in OS_TYPE:
		import utmp
		with open("/var/log/wtmp", "rb") as fd:
			buf = fd.read()
			for entry in utmp.read(buf):
				if(str(entry.type) == "UTmpRecordType.user_process"):
					dateObject = datetime.datetime.utcfromtimestamp(entry.sec)
					users.append({
						"username": entry.user,
						"console": entry.line,
						"timestamp": dateObject.strftime("%Y-%m-%d %H:%M:%S")
					})
	elif "darwin" in OS_TYPE:
		command = "last"
		entries = os.popen(command).read().replace("\t"," ").split("\n")
		for entry in entries:
			parts = " ".join(entry.split()).split(" ", 2)
			if(len(parts) == 3 and parts[1] != "~" and parts[0] != "wtmp"):
				rawTimestamp = " ".join(parts[2].split(" ", 4)[:-1])
				dateObject = datetime.datetime.strptime(rawTimestamp, "%a %b %d %H:%M")
				dateObject = dateObject.replace(tzinfo=tz.tzlocal()) # UTC time
				if(dateObject.year == 1900): dateObject = dateObject.replace(year=datetime.date.today().year)
				users.append({
					"username": parts[0],
					"console": parts[1],
					"timestamp": dateObject.astimezone(tz.tzutc()).strftime("%Y-%m-%d %H:%M:%S")
				})
	return users

def removeAll(path):
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			os.remove(os.path.join(root, name))
		for name in dirs:
			os.rmdir(os.path.join(root, name))
	os.rmdir(path)

def jsonRequest(method, data):
	# compile request header and payload
	headers = {"content-type": "application/json"}
	data = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": method,
		"params": {
			"client-key": apikey,
			"data": data
		}
	}
	data_json = json.dumps(data)

	# send request
	response = requests.post(apiurl, data=data_json, headers=headers)

	# print response
	print(response)
	print(response.text)

	# return response
	return response

##### MAIN #####

# check if already running (e.g. due to long running software jobs)
LOCKFILE_PATH = tempfile.gettempdir()+'/oco.agent.lock'
try:
	# if we can open the lockfile without error, no other instance is running
	with open(LOCKFILE_PATH, 'x') as lockfile:
		pid = str(os.getpid())
		lockfile.write(pid)
		print("OCO Agent starting (pid "+pid+")...")
except IOError:
	# there is a lock file - check if pid from lockfile is still active
	with open(LOCKFILE_PATH, 'r') as lockfile:
		oldpid = -1
		try: oldpid = int(lockfile.read().strip())
		except ValueError: pass
		lockfile.close()
		if(psutil.pid_exists(oldpid)):
			# another instance is still running -> exit
			print("OCO Agent already running at pid "+str(oldpid)+". Exiting.")
			sys.exit()
		else:
			# process is not running anymore -> delete lockfile and start agent
			print("Cleaning up orphaned lockfile (pid "+str(oldpid)+" is not running anymore) and starting OCO Agent...")
			os.unlink(LOCKFILE_PATH)
			with open(LOCKFILE_PATH, 'x') as lockfile:
				pid = str(os.getpid())
				lockfile.write(pid)
				print("OCO Agent starting (pid "+pid+")...")

# read config
try:
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument("--config", default="./oco-agent.ini", type=str)
	args = parser.parse_args()
	configParser = configparser.RawConfigParser()
	configParser.read(args.config)
	apiurl = configParser.get("server", "api-url")
	payloadurl = configParser.get("server", "payload-url")
	apikey = configParser.get("server", "client-key")
except Exception as e:
	print(str(e))
	sys.exit(1)

# send initial request
data = {
	"agent_version": AGENT_VERSION,
	"hostname": socket.gethostname(),
	"networks": getNics(),
}
request = jsonRequest("oco.client_hello", data)

# check response
if(request.status_code == 200):
	responseJson = request.json()

	# send computer info if requested
	if(responseJson["result"]["params"]["update"] == 1):
		data = {
			'agent_version': AGENT_VERSION,
			'hostname': socket.gethostname(),
			'os': getOs(),
			'os_version': getOsVersion(),
			'os_license': getIsActivated(),
			'os_language': getLocale(),
			'kernel_version': getKernelVersion(),
			'architecture': platform.machine(),
			'cpu': getCpu(),
			'ram': virtual_memory().total,
			'gpu': getGpu(),
			'serial': getMachineSerial(),
			'manufacturer': getMachineManufacturer(),
			'model': getMachineModel(),
			'bios_version': getBiosVersion(),
			'boot_type': getUefiOrBios(),
			'secure_boot': getSecureBootEnabled(),
			'networks': getNics(),
			'drives': getDrives(),
			'screens': getScreens(),
			'printer': getPrinter(),
			'software': getInstalledSoftware(),
			'logins': getLogins()
		}
		request = jsonRequest('oco.client_update', data)

	# execute jobs if requested
	if(len(responseJson['result']['params']['software-jobs']) > 0):
		for job in responseJson['result']['params']['software-jobs']:
			try:

				print('Begin Software Job '+str(job['id']))
				jsonRequest('oco.update_deploy_status', {'job-id': job['id'], 'state': 1, 'message': ''})

				tempZipPath = tempfile.gettempdir()+'/oco-staging.zip'
				tempPath = tempfile.gettempdir()+'/oco-staging'

				payloadparams = { 'client-key' : apikey, 'id' : job['package_id'] }
				urllib.request.urlretrieve(payloadurl+'?'+urllib.parse.urlencode(payloadparams), tempZipPath)

				if(os.path.exists(tempPath)): removeAll(tempPath)
				os.mkdir(tempPath)

				with ZipFile(tempZipPath, 'r') as zipObj:
					zipObj.extractall(tempPath)

				if(job['procedure'] != ""):
					os.chdir(tempPath)
					res = subprocess.run(job['procedure'], shell=True, capture_output=True)
					if res.returncode == 0:
						jsonRequest('oco.update_deploy_status', {'job-id': job['id'], 'state': 2, 'message': res.stdout})
					else:
						jsonRequest('oco.update_deploy_status', {'job-id': job['id'], 'state': -1, 'message': res.stderr})

				removeAll(tempPath)

			except Exception as e:
				print(str(e))
				jsonRequest('oco.update_deploy_status', {'job-id': job['id'], 'state': -1, 'message': str(e)})

lockfile.close()
os.unlink(LOCKFILE_PATH)
print("Closing lockfile and exiting.")