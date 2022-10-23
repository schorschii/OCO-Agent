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
import configparser
import argparse
import psutil
import atexit
from psutil import virtual_memory
import distro
import time
import datetime
from dateutil import tz
import tempfile
import subprocess
import shlex
import pyedid
from zipfile import ZipFile
from dns import resolver, rdatatype


##### CONSTANTS #####

AGENT_VERSION = "0.15.3"
EXECUTABLE_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
DEFAULT_CONFIG_PATH = EXECUTABLE_PATH+"/oco-agent.ini"
LOCKFILE_PATH = tempfile.gettempdir()+'/oco-agent.lock'
SERVICE_CHECKS_PATH = EXECUTABLE_PATH+"/service-checks"
OS_TYPE = sys.platform.lower()


##### OS SPECIFIC IMPORTS #####

if "win32" in OS_TYPE:
	import wmi, winreg
	from winevt import EventLog
	from win32com.client import GetObject
elif "linux" in OS_TYPE:
	import utmp
	SERVICE_CHECKS_PATH = "/usr/lib/oco-agent/service-checks"
elif "darwin" in OS_TYPE:
	import plistlib


##### GLOBAL VARIABLES #####

restartFlag = False
config = {
	"debug": False,
	"connection-timeout": 3.05,
	"read-timeout": 120,
	"query-interval": 60,
	"agent-key": "",
	"api-url": "",
	"server-key": "",
	"linux": {},
	"macos": {},
	"windows": {
		"username-with-domain": False
	}
}


##### INVENTORY FUNCTIONS #####

def getHostname():
	hostname = socket.gethostname()
	if "darwin" in OS_TYPE:
		if('.' in hostname): hostname = hostname.split('.', 1)[0]
	return hostname

def getNics():
	nics = []
	mentionedMacs = []
	for interface in netifaces.interfaces():
		ifaddrs = netifaces.ifaddresses(interface)
		interface = str(interface)
		if(netifaces.AF_INET in ifaddrs):
			for ineta in ifaddrs[netifaces.AF_INET]:
				if(ineta["addr"] == "127.0.0.1"): continue
				addr = ineta["addr"]
				netmask = ineta["netmask"] if "netmask" in ineta else "-"
				broadcast = ineta["broadcast"] if "broadcast" in ineta else "-"
				if(not netifaces.AF_LINK in ifaddrs or len(ifaddrs[netifaces.AF_LINK]) == 0):
					nics.append({"addr":addr, "netmask":netmask, "broadcast":broadcast, "mac":"-", "interface":interface})
				else:
					for ether in ifaddrs[netifaces.AF_LINK]:
						mentionedMacs.append(ether["addr"])
						nics.append({"addr":addr, "netmask":netmask, "broadcast":broadcast, "mac":ether["addr"], "interface":interface})
		if(netifaces.AF_INET6 in ifaddrs):
			for ineta in ifaddrs[netifaces.AF_INET6]:
				if(ineta["addr"] == "::1"): continue
				if(ineta["addr"].startswith("fe80")): continue
				addr = ineta["addr"]
				netmask = ineta["netmask"] if "netmask" in ineta else "-"
				broadcast = ineta["broadcast"] if "broadcast" in ineta else "-"
				if(not netifaces.AF_LINK in ifaddrs or len(ifaddrs[netifaces.AF_LINK]) == 0):
					nics.append({"addr":addr, "netmask":netmask, "broadcast":broadcast, "mac":"-", "interface":interface})
				else:
					for ether in ifaddrs[netifaces.AF_LINK]:
						mentionedMacs.append(ether["addr"])
						nics.append({"addr":addr, "netmask":netmask, "broadcast":broadcast, "mac":ether["addr"], "interface":interface})
		if(netifaces.AF_LINK in ifaddrs):
			for ether in ifaddrs[netifaces.AF_LINK]:
				if(ether["addr"].strip() == ""): continue
				if(ether["addr"].startswith("00:00:00:00:00:00")): continue
				if(not ether["addr"] in mentionedMacs):
					nics.append({"addr":"-", "netmask":"-", "broadcast":"-", "mac":ether["addr"], "interface":interface})
	return nics

def getOs():
	if "win32" in OS_TYPE:
		try:
			registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ)
			productName, regtype = winreg.QueryValueEx(registry_key, "ProductName")
			return str(productName)
			winreg.CloseKey(registry_key)
		except WindowsError: return platform.system()
	elif "linux" in OS_TYPE:
		return distro.name()
	elif "darwin" in OS_TYPE:
		return "macOS"

def getOsVersion():
	if "win32" in OS_TYPE:
		try:
			registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ)
			try:
				# read CurrentMajorVersionNumber/CurrentMinorVersionNumber if exists (only Windows 10)
				# the value "CurrentVersion" always shows "6.3" on Windows 10, great job Microsoft...
				valueMajor, regtype = winreg.QueryValueEx(registry_key, "CurrentMajorVersionNumber")
				valueMinor, regtype = winreg.QueryValueEx(registry_key, "CurrentMinorVersionNumber")
				valueBuild, regtype = winreg.QueryValueEx(registry_key, "CurrentBuildNumber")
				winreg.CloseKey(registry_key)
				return str(valueMajor)+"."+str(valueMinor)+"."+str(valueBuild)
			except WindowsError: pass
			try:
				# fallback: read CurrentVersion on older Windows versions
				valueVersion, regtype = winreg.QueryValueEx(registry_key, "CurrentVersion")
				valueBuild, regtype = winreg.QueryValueEx(registry_key, "CurrentBuildNumber")
				winreg.CloseKey(registry_key)
				return str(valueVersion)+"."+str(valueBuild)
			except WindowsError: return "?"
		except WindowsError: return "?"
	elif "linux" in OS_TYPE:
		return distro.version()
	elif "darwin" in OS_TYPE:
		return platform.mac_ver()[0]

def getUptime():
	return time.time() - psutil.boot_time()

def getKernelVersion():
	if "win32" in OS_TYPE:
		return "-"
	elif "linux" in OS_TYPE or "darwin" in OS_TYPE:
		return platform.release()

def getMachineUid():
	uid = ""
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_ComputerSystemProduct(): uid = o.UUID
	elif "linux" in OS_TYPE:
		command = "dmidecode -s system-uuid"
		uid = os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")
	elif "darwin" in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
		uid = os.popen(command).read().replace("\n","").replace("\t","").replace(" ","")
	if uid.strip() == "": uid = getHostname() # fallback
	return uid

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
		res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
		if res.returncode == 0:
			booted = "UEFI" if "EFI" in res.stdout else "Legacy"
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

def queryRegistrySoftware(key):
	software = []
	reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
	ids = []
	try:
		count = 0
		while True:
			name = winreg.EnumKey(reg, count)
			count = count + 1
			ids.append(name)
	except WindowsError: pass
	winreg.CloseKey(reg)
	for name in ids:
		try:
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key+"\\"+name, 0, winreg.KEY_READ)
			displayName, regtype = winreg.QueryValueEx(reg, "DisplayName")
			displayVersion = ""
			displayPublisher = ""
			systemComponent = 0
			try: displayVersion, regtype = winreg.QueryValueEx(reg, "DisplayVersion")
			except WindowsError: pass
			try: displayPublisher, regtype = winreg.QueryValueEx(reg, "Publisher")
			except WindowsError: pass
			try: systemComponent, regtype = winreg.QueryValueEx(reg, "SystemComponent")
			except WindowsError: pass
			winreg.CloseKey(reg)
			if(displayName.strip() == "" or systemComponent == 1): continue
			software.append({
				"name": displayName,
				"version": displayVersion,
				"description": displayPublisher
			})
		except WindowsError: pass
	return software
def getInstalledSoftware():
	software = []
	if "win32" in OS_TYPE:
		x64software = queryRegistrySoftware("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
		x32software = queryRegistrySoftware("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
		software = x32software + x64software
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
		appdirname = "/Applications"
		appdir = os.fsencode(appdirname)
		for app in os.listdir(appdir):
			appname = os.fsdecode(app)
			if(not os.path.isfile(appname) and appname.endswith(".app")):
				infoPlstPath = os.path.join(appdirname, appname, "Contents", "Info.plist")
				if(not os.path.isfile(infoPlstPath)): continue
				with open(infoPlstPath, "rb") as f:
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
	elif "darwin" in OS_TYPE:
		try:
			command = "osascript -e 'user locale of (get system info)'"
			return os.popen(command).read().strip()
		except Exception as e: print(logtime()+str(e))
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
		try:
			command = "system_profiler SPDisplaysDataType -json"
			jsonstring = os.popen(command).read().strip()
			jsondata = json.loads(jsonstring)
			for gpu in jsondata["SPDisplaysDataType"]:
				return gpu["sppci_model"]
		except Exception as e: return "?"

def getLinuxXAuthority():
	try:
		# LightDM
		for i in range(10):
			checkFile = "/var/run/lightdm/root/:"+str(i)
			if(os.path.exists(checkFile)):
				return {"file":checkFile, "display":":"+str(i)}
		# GDM
		command = "who|grep -E '\(:[0-9](\.[0-9])*\)'|awk '{print $1$NF}'|sort -u"
		for l in os.popen(command).read().split("\n"):
			if(l.strip() == ""): continue
			display = l.split("(")[1].split(")")[0]
			username = l.split("(")[0]
			userid = os.popen("id -u "+shlex.quote(username)).read().strip()
			checkFile = "/run/user/"+str(int(userid))+"/gdm/Xauthority"
			if(os.path.exists(checkFile)):
				return {"file":checkFile, "display":display}
	except Exception as e:
		print(logtime()+str(e))
	return None
def getScreens():
	screens = []
	if "win32" in OS_TYPE:
		try:
			objWMI = GetObject(r'winmgmts:\\.\root\WMI').InstancesOf('WmiMonitorID')
			for monitor in objWMI:
				try:
					devPath = monitor.InstanceName.split('_')[0]
					regPath = 'SYSTEM\\CurrentControlSet\\Enum\\'+devPath+'\\Device Parameters'
					registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, regPath, 0, winreg.KEY_READ)
					edid, regtype = winreg.QueryValueEx(registry_key, "EDID")
					winreg.CloseKey(registry_key)
					if not edid: continue
					#print ('DEBUG: EDID Version: '+str(edid[18])+'.'+str(edid[19]))
					#dtd = 54  # start byte of detailed timing desc.
					# upper nibble of byte x 2^8 combined with full byte
					#hres = ((edid[dtd+4] >> 4) << 8) | edid[dtd+2]
					#vres = ((edid[dtd+7] >> 4) << 8) | edid[dtd+5]
					edidp = pyedid.parse_edid(edid)
					manufacturer = edidp.manufacturer or "Unknown"
					if(manufacturer == "Unknown"): manufacturer += " ("+str(edidp.manufacturer_id)+")"
					screens.append({
						"name": edidp.name,
						"manufacturer": manufacturer,
						"manufactured": str(edidp.year or "-"),
						"resolution": str(edidp.resolutions[-1][0])+" x "+str(edidp.resolutions[-1][1]),
						"size": str(edidp.width)+" x "+str(edidp.height),
						"type": str(edidp.product_id or "-"),
						"serialno": edidp.serial or "-",
						"technology": str(edidp.type or "-")
					})
				except Exception as e: print(logtime()+str(e))
		except Exception as e: print(logtime()+str(e))
	elif "linux" in OS_TYPE:
		try:
			xAuthority = getLinuxXAuthority()
			if(xAuthority != None):
				os.environ["XAUTHORITY"] = xAuthority['file']
				os.environ["DISPLAY"] = xAuthority['display']
			randr = subprocess.check_output(['xrandr', '--verbose'])
			for edid in pyedid.get_edid_from_xrandr_verbose(randr):
				try:
					edidp = pyedid.parse_edid(edid)
					manufacturer = edidp.manufacturer or "Unknown"
					if(manufacturer == "Unknown"): manufacturer += " ("+str(edidp.manufacturer_id)+")"
					screens.append({
						"name": edidp.name,
						"manufacturer": manufacturer,
						"manufactured": str(edidp.year or "-"),
						"resolution": str(edidp.resolutions[-1][0])+" x "+str(edidp.resolutions[-1][1]),
						"size": str(edidp.width)+" x "+str(edidp.height),
						"type": str(edidp.product_id or "-"),
						"serialno": edidp.serial or "-",
						"technology": str(edidp.type or "-")
					})
				except Exception as e: print(logtime()+str(e))
		except Exception as e: print(logtime()+str(e))
	elif "darwin" in OS_TYPE:
		try:
			command = "system_profiler SPDisplaysDataType -json"
			jsonstring = os.popen(command).read().strip()
			jsondata = json.loads(jsonstring)
			for gpu in jsondata["SPDisplaysDataType"]:
				for screen in gpu["spdisplays_ndrvs"]:
					try:
						edidp = pyedid.parse_edid(screen["_spdisplays_edid"].replace("0x",""))
						manufacturer = edidp.manufacturer or "Unknown"
						resolution = "-" # MacBook internal screens do not provide resolution data :'(
						if(manufacturer == "Unknown"): manufacturer += " ("+str(edidp.manufacturer_id)+")"
						if(len(edidp.resolutions) > 0): resolution = str(edidp.resolutions[-1][0])+" x "+str(edidp.resolutions[-1][1])
						screens.append({
							"name": edidp.name,
							"manufacturer": manufacturer,
							"manufactured": str(edidp.year or "-"),
							"resolution": resolution,
							"size": str(edidp.width)+" x "+str(edidp.height),
							"type": str(edidp.product_id or "-"),
							"serialno": edidp.serial or "-",
							"technology": str(edidp.type or "-")
						})
					except Exception as e: print(logtime()+str(e))
		except Exception as e: print(logtime()+str(e))
	return screens

def winPrinterStatus(status, state):
	if(state == 2): return "Error";
	if(state == 8): return "Paper Jam";
	if(state == 16): return "Out Of Paper";
	if(state == 64): return "Paper Problem";
	if(state == 131072): return "Toner Low";
	if(state == 262144): return "No Toner";
	if(status == 1): return "Other";
	if(status == 3): return "Idle";
	if(status == 4): return "Printing";
	if(status == 5): return "Warmup";
	if(status == 6): return "Stopped";
	if(status == 7): return "Offline";
	return "Unknown";
def getPrinters():
	printers = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Printer():
			printers.append({
				"name": o.Name,
				"driver": o.DriverName,
				"paper": "" if o.PrinterPaperNames == None else ", ".join(o.PrinterPaperNames),
				"dpi": o.HorizontalResolution,
				"uri": o.PortName,
				"status": winPrinterStatus(o.PrinterStatus, o.PrinterState)
			})
	elif "linux" in OS_TYPE or "darwin" in OS_TYPE:
		CUPS_CONFIG = "/etc/cups/printers.conf"
		if(not os.path.exists(CUPS_CONFIG)): return printers
		with open(CUPS_CONFIG, 'r', encoding='utf-8', errors='replace') as file:
			printer = {"name": "", "driver": "", "paper": "", "dpi": "", "uri": "", "status": ""}
			for line in file:
				l = line.rstrip("\n")
				if(l.startswith("<DefaultPrinter ") or l.startswith("<Printer ")):
					printer = {
						"name": l.split(" ", 1)[1].rstrip(">"),
						"driver": "", "paper": "", "dpi": "", "uri": "", "status": ""
					}
				if(l.startswith("MakeModel ")):
					printer["driver"] = l.split(" ", 1)[1]
				if(l.startswith("DeviceURI ")):
					printer["uri"] = l.split(" ", 1)[1]
				if(l.startswith("</DefaultPrinter>") or l.startswith("</Printer>")):
					if(printer["name"] != ""): printers.append(printer)
	return printers

def getPartitions():
	partitions = []
	if "win32" in OS_TYPE:
		w = wmi.WMI()
		for ld in w.Win32_LogicalDisk():
			devicePath = "?"
			for v in w.Win32_Volume():
				if(v.DriveLetter == ld.DeviceID):
					devicePath = v.DeviceID
			partitions.append({
				"device": devicePath,
				"mountpoint": ld.DeviceID,
				"filesystem": ld.FileSystem,
				"name": ld.VolumeName,
				"size": ld.Size,
				"free": ld.FreeSpace,
				"serial": ld.VolumeSerialNumber
			})
	elif "linux" in OS_TYPE:
		command = "df -k --output=used,avail,fstype,source,target"
		lines = os.popen(command).read().strip().splitlines()
		first = True
		for line in lines:
			if(first): first = False; continue
			values = " ".join(line.split()).split()
			if(len(values) != 5): continue
			if(values[2] == "tmpfs" or values[2] == "devtmpfs"): continue
			partitions.append({
				"device": values[3],
				"mountpoint": values[4],
				"filesystem": values[2],
				"size": (int(values[0])+int(values[1]))*1024,
				"free": int(values[1])*1024,
				"name": "",
				"serial": ""
			})
	elif "darwin" in OS_TYPE:
		command = "df -k"
		lines = os.popen(command).read().strip().splitlines()
		first = True
		for line in lines:
			if(first): first = False; continue
			values = " ".join(line.split()).split()
			if(len(values) != 9): continue
			if(values[0] == "devfs"): continue
			partitions.append({
				"device": values[0],
				"mountpoint": values[8],
				"filesystem": "",
				"size": (int(values[2])+int(values[3]))*1024,
				"free": int(values[3])*1024,
				"name": "",
				"serial": ""
			})
	return partitions

def queryRegistryUserDisplayName(querySid):
	# get user fullname from SessionData cache in registry
	try:
		key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\SessionData"
		reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
		count = 0
		while True:
			name = winreg.EnumKey(reg, count)
			count = count + 1
			reg2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key+"\\"+name, 0, winreg.KEY_READ)
			sid, regtype = winreg.QueryValueEx(reg2, "LoggedOnUserSID")
			if querySid == sid:
				displayName, regtype = winreg.QueryValueEx(reg2, "LoggedOnDisplayName")
				return displayName
	except WindowsError as e: pass
	return ""
def queryRegistryUserGuid(querySid):
	# get user GUID from ProfileList in registry
	try:
		key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"+querySid
		reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
		guid, regtype = winreg.QueryValueEx(reg, "Guid")
		return guid.strip("{}")
	except WindowsError as e: pass
	return None
def getLogins(since):
	users = []
	dateObjectSince = datetime.datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
	if "win32" in OS_TYPE:
		# Logon Types
		#  2: Interactive (local console)
		#  3: Network (access to network shares and printers)
		#  4: Batch (scheduled tasks)
		#  5: Service
		#  7: Unlock
		#  8: NetworkCleartext
		#  9: NewCredentials (users executes program as another user using "runas")
		#  10: RemoteInteractive (RDP)
		#  11: CachedInteractive (local console without connection to AD server)
		try:
			query = EventLog.Query("Security", "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[(EventData[Data[@Name='LogonType']='2'] or EventData[Data[@Name='LogonType']='10'] or EventData[Data[@Name='LogonType']='11']) and System[(EventID='4624')]]</Select></Query></QueryList>")
			consolidatedEventList = []
			for event in query:
				eventDict = { "TargetUserSid":"", "TargetUserName":"", "TargetDomainName":"", "LogonType":"", "IpAddress":"", "LogonProcessName":"",
					"TimeCreated":event.System.TimeCreated["SystemTime"] }
				# put data of interest to dict
				for data in event.EventData.Data:
					if(data["Name"] in ["TargetUserSid", "TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "LogonProcessName"]):
						eventDict[data["Name"]] = data.cdata
				# eliminate duplicates and curious system logins
				if eventDict not in consolidatedEventList and eventDict["LogonProcessName"].strip() == "User32":
					consolidatedEventList.append(eventDict)
			for event in consolidatedEventList:
				# example timestamp: 2021-04-09T13:47:14.719737700Z
				dateObject = datetime.datetime.strptime(event["TimeCreated"].split(".")[0], "%Y-%m-%dT%H:%M:%S")
				if(dateObject <= dateObjectSince): continue
				users.append({
					"guid": queryRegistryUserGuid(event["TargetUserSid"]),
					"display_name": queryRegistryUserDisplayName(event["TargetUserSid"]),
					"username": event["TargetDomainName"]+"\\"+event["TargetUserName"] if config["windows"]["username-with-domain"] else event["TargetUserName"],
					"console": event["IpAddress"],
					"timestamp": dateObject.strftime("%Y-%m-%d %H:%M:%S")
				})
		except Exception as e:
			print(logtime()+str(e))
	elif "linux" in OS_TYPE:
		with open("/var/log/wtmp", "rb") as fd:
			buf = fd.read()
			for entry in utmp.read(buf):
				if(str(entry.type) == "UTmpRecordType.user_process"):
					dateObject = datetime.datetime.utcfromtimestamp(entry.sec)
					if(dateObject <= dateObjectSince): continue
					users.append({
						"display_name": os.popen("getent passwd "+shlex.quote(entry.user)+" | cut -d : -f 5").read().strip().rstrip(","),
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
				if(dateObject <= dateObjectSince): continue
				users.append({
					"display_name": os.popen("id -F "+shlex.quote(parts[0])).read().strip(),
					"username": parts[0],
					"console": parts[1],
					"timestamp": dateObject.astimezone(tz.tzutc()).strftime("%Y-%m-%d %H:%M:%S")
				})
	return users

def getEvents(log, query, since):
	foundEvents = []
	try:
		dateObjectSince = datetime.datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
		if "win32" in OS_TYPE:
			startTime = time.time()
			print(logtime()+"Querying events from "+log+"...")
			query = EventLog.Query(log, query)
			for event in query:
				dateObject = datetime.datetime.strptime(event.System.TimeCreated["SystemTime"].split(".")[0], "%Y-%m-%dT%H:%M:%S")
				if(dateObject <= dateObjectSince): continue
				eventDict = {"log": log, "provider": event.System.Provider["Name"], "event_id": event.EventID, "level": event.Level, "timestamp":dateObject.strftime("%Y-%m-%d %H:%M:%S"), "data":{}}
				for data in event.EventData.children:
					eventDict["data"][data['Name']] = str(data.cdata)
				foundEvents.append(eventDict)
			if(config["debug"]): print("  took "+str(time.time()-startTime))
	except Exception as e:
		print(logtime()+str(e))
	return foundEvents

def getServiceStatus():
	services = []
	if not os.path.exists(SERVICE_CHECKS_PATH): return
	for file in [f for f in os.listdir(SERVICE_CHECKS_PATH) if os.path.isfile(os.path.join(SERVICE_CHECKS_PATH, f))]:
		serviceScriptPath = os.path.join(SERVICE_CHECKS_PATH, file)
		startTime = time.time()
		print(logtime()+"Executing service check script "+serviceScriptPath+"...")
		res = subprocess.run(serviceScriptPath, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
		# example output (CheckMK format): 0 "My service" myvalue=73;80;90 My output text
		# https://docs.checkmk.com/latest/de/localchecks.html
		for line in guessEncodingAndDecode(res.stdout).splitlines():
			values = shlex.split(line)
			if(len(values) < 4):
				print("  invalid output from script: "+line)
				continue
			services.append({"status":values[0], "name":values[1], "merics":values[2], "details":" ".join(values[3:])})
		if(config["debug"]): print("  took "+str(time.time()-startTime))
	return services


##### AGENT-SERVER COMMUNICATION FUNCTIONS #####

def downloadFile(url, params, path):
	with requests.get(url, params=params, stream=True, timeout=(config["connection-timeout"],config["read-timeout"])) as r:
		r.raise_for_status()
		with open(path, 'wb') as f:
			for chunk in r.iter_content(chunk_size=8192): 
				f.write(chunk)

def jsonRequest(method, data):
	headers = {"content-type": "application/json"}
	data = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": method,
		"params": {
			"uid": getMachineUid(),
			"hostname": getHostname(),
			"agent-key": config["agent-key"],
			"data": data
		}
	}
	data_json = json.dumps(data)

	try:
		# send request
		if(config["debug"]): print(logtime()+"< " + data_json)
		response = requests.post(config["api-url"], data=data_json, headers=headers, timeout=(config["connection-timeout"],config["read-timeout"]))

		# print response
		if(config["debug"]): print(logtime()+"> (" + str(response.elapsed.total_seconds()) + "s) [" + str(response.status_code) + "] " + response.text)
		if(response.status_code != 200):
			print(logtime()+"Request failed with HTTP status code " + str(response.status_code))

		# return response
		return response

	except Exception as e:
		print(logtime()+str(e))
		return None


##### VARIOUS AGENT FUNCTIONS #####

def isUserLoggedIn():
	if "win32" in OS_TYPE:
		w=wmi.WMI()
		for u in w.Win32_Process(Name="explorer.exe"):
			return True
	elif "linux" in OS_TYPE:
		command = "who"
		entries = os.popen(command).read().split("\n")
		for entry in entries:
			if(entry.strip() != ""):
				return True
	elif "darwin" in OS_TYPE:
		return True # not implemented
	return False

def removeAll(path):
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			os.remove(os.path.join(root, name))
		for name in dirs:
			os.rmdir(os.path.join(root, name))
	os.rmdir(path)

def logtime():
	return "["+str(datetime.datetime.now())+"] "

def guessEncodingAndDecode(textBytes, codecs=['utf-8', 'cp1252', 'cp850']):
	for codec in codecs:
		try:
			return textBytes.decode(codec)
		except UnicodeDecodeError: pass
	return textBytes.decode(sys.stdout.encoding, 'replace') # fallback: replace invalid characters

# function for checking if agent is already running (e.g. due to long running software jobs)
def lockCheck():
	try:
		# if we can open the lockfile without error, no other instance is running
		with open(LOCKFILE_PATH, 'x') as lockfile:
			pid = str(os.getpid())
			lockfile.write(pid)
			print(logtime()+"OCO Agent starting with lock file (pid "+pid+")...")
	except IOError:
		# there is a lock file - check if pid from lockfile is still active
		with open(LOCKFILE_PATH, 'r') as lockfile:
			oldpid = -1
			try: oldpid = int(lockfile.read().strip())
			except ValueError: pass
			lockfile.close()
			alreadyRunning = False
			try:
				p = psutil.Process(oldpid)
				if(not p.exe() is None):
					if("oco" in p.exe() or "python" in p.exe()): alreadyRunning = True
			except Exception: pass
			if(alreadyRunning):
				# another instance is still running -> exit
				print(logtime()+"OCO Agent already running at pid "+str(oldpid)+" (lock file "+LOCKFILE_PATH+"). Exiting.")
				sys.exit()
			else:
				# process is not running anymore -> delete lockfile and start agent
				print(logtime()+"Cleaning up orphaned lock file (pid "+str(oldpid)+" is not running anymore) and starting OCO Agent...")
				os.unlink(LOCKFILE_PATH)
				with open(LOCKFILE_PATH, 'x') as lockfile:
					pid = str(os.getpid())
					lockfile.write(pid)
					print(logtime()+"OCO Agent starting with lock file (pid "+pid+")...")
	atexit.register(lockClean, lockfile)
# clean up lockfile
def lockClean(lockfile):
	lockfile.close()
	os.unlink(LOCKFILE_PATH)
	print(logtime()+"Closing lock file and exiting.")


##### AGENT MAIN LOOP #####

def daemon():
	while(True):
		try: mainloop()
		except KeyError as e: print(logtime()+"KeyError: "+str(e))
		print(logtime()+"Running in daemon mode. Waiting "+str(config["query-interval"])+" seconds to send next request.")
		time.sleep(config["query-interval"])

# the main server communication function
# sends a "agent_hello" packet to the server and then executes various tasks, depending on the server's response
def mainloop():
	global restartFlag

	# send initial request
	print(logtime()+"Sending agent_hello...")
	data = {
		"agent_version": AGENT_VERSION,
		"networks": getNics(),
		"services": getServiceStatus(),
	}
	request = jsonRequest("oco.agent.hello", data)

	# check response
	if(request != None and request.status_code == 200):
		responseJson = request.json()

		# save server key if server key is not already set in local config
		if(config["server-key"] == None or config["server-key"] == ""):
			print(logtime()+"Write new config with updated server key...")
			configParser.set("server", "server-key", responseJson["result"]["params"]["server-key"])
			with open(args.config, 'w') as fileHandle: configParser.write(fileHandle)
			config["server-key"] = configParser.get("server", "server-key")

		# check server key
		if(config["server-key"] != responseJson["result"]["params"]["server-key"]):
			print(logtime()+"!!! Invalid server key, abort.")
			return

		# update agent key if requested
		if(responseJson["result"]["params"]["agent-key"] != None):
			print(logtime()+"Write new config with updated agent key...")
			configParser.set("agent", "agent-key", responseJson["result"]["params"]["agent-key"])
			with open(args.config, 'w') as fileHandle: configParser.write(fileHandle)
			config["agent-key"] = configParser.get("agent", "agent-key")

		# send computer info if requested
		loginsSince = "2000-01-01 00:00:00"
		if("logins-since" in responseJson["result"]["params"]):
			loginsSince = responseJson["result"]["params"]["logins-since"]
		if(responseJson["result"]["params"]["update"] == 1):
			print(logtime()+"Updating inventory data...")
			data = {
				'hostname': getHostname(),
				'agent_version': AGENT_VERSION,
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
				'uptime': getUptime(),
				'boot_type': getUefiOrBios(),
				'secure_boot': getSecureBootEnabled(),
				'domain': socket.getfqdn(),
				'networks': getNics(),
				'screens': getScreens(),
				'printers': getPrinters(),
				'partitions': getPartitions(),
				'software': getInstalledSoftware(),
				'logins': getLogins(loginsSince)
			}
			request = jsonRequest('oco.agent.update', data)

		# execute jobs if requested
		if(len(responseJson['result']['params']['software-jobs']) > 0):
			ignoreContainerIds = []
			for job in responseJson['result']['params']['software-jobs']:
				if('container-id' in job and job['container-id'] in ignoreContainerIds):
					print(logtime()+'Skipping Software Job '+str(job['id'])+' because container id '+str(job['container-id'])+' should be ignored.')
					continue
				if(job['procedure'].strip() == ''):
					print(logtime()+'Software Job '+str(job['id'])+': prodecure is empty - do nothing but send success message to server.')
					jsonRequest('oco.agent.update_job_state', {'job-id': job['id'], 'state': 3, 'return-code': 0, 'message': ''})
					continue
				if(restartFlag == True):
					print(logtime()+'Skipping Software Job '+str(job['id'])+' because restart flag is set.')
					continue

				try:

					# create temp dir
					print(logtime()+'Begin Software Job '+str(job['id']))
					tempZipPath = tempfile.gettempdir()+'/oco-staging.zip'
					tempPath = tempfile.gettempdir()+'/oco-staging'
					if(os.path.exists(tempPath)): removeAll(tempPath)
					os.mkdir(tempPath)

					# download if needed
					if(job['download'] == True):
						jsonRequest('oco.agent.update_job_state', {'job-id': job['id'], 'state': 1, 'return-code': 0, 'message': ''})

						payloadparams = { 'uid': getMachineUid(), 'hostname': getHostname(), 'agent-key': config['agent-key'], 'id': job['package-id'] }
						downloadFile(config['api-url'], payloadparams, tempZipPath)

						with ZipFile(tempZipPath, 'r') as zipObj:
							zipObj.extractall(tempPath)

					# change to tmp dir and execute procedure
					jsonRequest('oco.agent.update_job_state', {'job-id': job['id'], 'state': 2, 'return-code': 0, 'message': ''})
					os.chdir(tempPath)
					res = subprocess.run(job['procedure'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
					jobStatusRequest = jsonRequest('oco.agent.update_job_state', {'job-id': job['id'], 'state': 3, 'return-code': res.returncode, 'message': guessEncodingAndDecode(res.stdout)})

					# check server's update_job_state response
					# cancel pending jobs if sequence mode is 1 (= 'abort after failed') and job failed
					if('container-id' in job and 'sequence-mode' in job and job['sequence-mode'] == 1 and jobStatusRequest != None and jobStatusRequest.status_code == 200):
						jobStatusResponseJson = jobStatusRequest.json()
						jobSucceeded = True
						try:
							jobSucceeded = bool(jobStatusResponseJson['result']['params']['job-succeeded'])
						except KeyError: pass
						if(not jobSucceeded):
							print(logtime()+'Add container id '+str(job['container-id'])+' to ignore array because server told me that the current job failed and sequence mode is set to 1.')
							ignoreContainerIds.append(job['container-id'])
							os.chdir(tempfile.gettempdir())
							continue

					# cleanup
					os.chdir(tempfile.gettempdir())
					removeAll(tempPath)

					# execute restart if requested
					if('restart' in job and job['restart'] != None and isinstance(job['restart'], int) and job['restart'] >= 0):
						timeout = 0
						if(isUserLoggedIn()): timeout = int(job['restart'])
						if "win32" in OS_TYPE:
							res = subprocess.run('shutdown -r -t '+str(timeout*60), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True
						else:
							res = subprocess.run('shutdown -r +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True

					# execute shutdown if requested
					if('shutdown' in job and job['shutdown'] != None and isinstance(job['shutdown'], int) and job['shutdown'] >= 0):
						timeout = 0
						if(isUserLoggedIn()): timeout = int(job['shutdown'])
						if "win32" in OS_TYPE:
							res = subprocess.run('shutdown -s -t '+str(timeout*60), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True
						else:
							res = subprocess.run('shutdown -h +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True

					# execute agent exit if requested (for agent update)
					if('exit' in job and job['exit'] != None and isinstance(job['exit'], int) and job['exit'] >= 0):
						print(logtime()+'Agent Exit Requested. Bye...')
						sys.exit(0)

				except Exception as e:
					print(logtime()+str(e))
					jsonRequest('oco.agent.update_job_state', {'job-id': job['id'], 'state': -1, 'return-code': -9999, 'message': str(e)})
					os.chdir(tempfile.gettempdir())

		# send events from logs if requested
		if("events" in responseJson["result"]["params"]):
			events = []
			for eventQuery in responseJson["result"]["params"]["events"]:
				if not "log" in eventQuery or not "query" in eventQuery or not "since" in eventQuery: continue
				events += getEvents(eventQuery["log"], eventQuery["query"], eventQuery["since"])
			if(len(events) > 0):
				request = jsonRequest('oco.agent.events', {"events":events})

##### MAIN ENTRY POINT - AGENT INITIALIZATION #####

try:
	# read arguments
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, type=str)
	parser.add_argument("--daemon", action='store_true')
	args = parser.parse_args()
	configFilePath = args.config
	daemonMode = args.daemon
	print(logtime()+"OCO Agent starting with config file: "+configFilePath+" ...")

	# read config
	configParser = configparser.RawConfigParser()
	configParser.read(configFilePath)
	if(configParser.has_option("agent", "debug")): config["debug"] = (int(configParser.get("agent", "debug")) == 1)
	if(configParser.has_option("agent", "connection-timeout")): config["connection-timeout"] = int(configParser.get("agent", "connection-timeout"))
	if(configParser.has_option("agent", "read-timeout")): config["read-timeout"] = int(configParser.get("agent", "read-timeout"))
	if(configParser.has_option("agent", "query-interval")): config["query-interval"] = int(configParser.get("agent", "query-interval"))
	if(configParser.has_option("agent", "agent-key")): config["agent-key"] = configParser.get("agent", "agent-key")
	if(configParser.has_option("server", "api-url")): config["api-url"] = configParser.get("server", "api-url")
	if(configParser.has_option("server", "server-key")): config["server-key"] = configParser.get("server", "server-key")
	if(configParser.has_option("windows", "username-with-domain")): config["windows"]["username-with-domain"] = (int(configParser.get("windows", "username-with-domain")) == 1)

	# try server auto discovery
	if(config["api-url"].strip() == ""):
		print(logtime()+"Server API URL is empty - trying DNS auto discovery ...")
		try:
			res = resolver.query(qname=f"_oco._tcp", rdtype=rdatatype.SRV, lifetime=10)
			for srv in res.rrset:
				config["api-url"] = "https://"+str(srv.target)+":"+str(srv.port)+"/api-agent.php"
				print(logtime()+'DNS auto discovery found server: '+config["api-url"])
				configParser.set("server", "api-url", config["api-url"])
				with open(configFilePath, 'w') as fileHandle: configParser.write(fileHandle)
				break
		except Exception as e: print(logtime()+'DNS auto discovery failed: '+str(e))

except Exception as e:
	print(logtime()+str(e))
	sys.exit(1)

# execute the agent as daemon if requested
if(daemonMode == True):
	lockCheck()
	daemon()

# execute the agent once
else:
	lockCheck()
	try: mainloop()
	except KeyError as e:
		print(logtime()+"KeyError: "+str(e))
		sys.exit(1)
