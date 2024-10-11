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

try:
	import pip_system_certs.wrapt_requests
except ImportError:
	print('ATTENTION: unable to load pip_system_certs.wrapt_requests')

import signal
import threading
import requests
import json
import socket
import netifaces
import platform
import os, sys
import configparser
import argparse
import psutil
import atexit
from psutil import virtual_memory
import distro
import time
import datetime
import tempfile
import subprocess
import shlex
import pyedid
from zipfile import ZipFile
from dns import resolver, rdatatype


##### CONSTANTS #####

from . import __version__, logger
EXECUTABLE_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
DEFAULT_CONFIG_PATH = EXECUTABLE_PATH+'/oco-agent.ini'
LOCKFILE_PATH = tempfile.gettempdir()+'/oco-agent.lock'
SERVICE_CHECKS_PATH = EXECUTABLE_PATH+'/service-checks'
OS_TYPE = sys.platform.lower()


##### OS SPECIFIC IMPORTS #####

if 'win32' in OS_TYPE:
	import wmi, winreg, ctypes
	from win32com.client import GetObject
	from .windows.event_log import getLogins as getLoginsWindows
	from .windows.event_log import getEvents as getEventsWindows

elif 'linux' in OS_TYPE:
	from .linux.utmp import getLogins as getLoginsLinux
	from .linux.systemd import getEvents as getEventsLinux
	SERVICE_CHECKS_PATH = '/usr/lib/oco-agent/service-checks'

elif 'darwin' in OS_TYPE:
	import plistlib
	from .macos.utmpx import getLogins as getLoginsMac
	# set OpenSSL path to macOS defaults
	# (Github Runner sets this to /usr/local/etc/openssl@1.1/ which does not exist in plain macOS installations)
	os.environ['SSL_CERT_FILE'] = '/private/etc/ssl/cert.pem'
	os.environ['SSL_CERT_DIR']  = '/private/etc/ssl/certs'
	# system CA certs debugging
	#import ssl; print(ssl.get_default_verify_paths())
	#ctx = ssl.SSLContext(); ctx.load_default_certs(); print(ctx.get_ca_certs())


##### GLOBAL VARIABLES #####

exitEvent = threading.Event()
restartFlag = False
configParser = configparser.RawConfigParser()
config = {
	# Agent config
	'debug': False,
	'connection-timeout': 3.05,
	'read-timeout': 150,
	'query-interval': 60,
	'agent-key': '',
	'chunk-size': 8192, # download chunk size
	'report-frames': 8192, # report download progress every 64 MiB
	'report-job-output': 5, # report job output every x secs if new lines appeared
	'hostname-remove-domain': True,
	'machine-uid': '',
	# Platform specific agent config
	'linux': {},
	'macos': {},
	'windows': {
		'username-with-domain': False
	},
	# Server config
	'api-url': '',
	'server-key': '',
}


##### INVENTORY FUNCTIONS #####

def getHostname():
	hostname = socket.gethostname()
	if(config['hostname-remove-domain'] and '.' in hostname):
		hostname = hostname.split('.', 1)[0]
	return hostname

def getNics():
	nics = []
	mentionedMacs = []
	for interface in netifaces.interfaces():
		ifaddrs = netifaces.ifaddresses(interface)
		interface = str(interface)
		if(netifaces.AF_INET in ifaddrs):
			for ineta in ifaddrs[netifaces.AF_INET]:
				if(ineta['addr'] == '127.0.0.1'): continue
				addr = ineta['addr']
				netmask = ineta['netmask'] if 'netmask' in ineta else '-'
				broadcast = ineta['broadcast'] if 'broadcast' in ineta else '-'
				if(not netifaces.AF_LINK in ifaddrs or len(ifaddrs[netifaces.AF_LINK]) == 0):
					nics.append({'addr':addr, 'netmask':netmask, 'broadcast':broadcast, 'mac':'-', 'interface':interface})
				else:
					for ether in ifaddrs[netifaces.AF_LINK]:
						mentionedMacs.append(ether['addr'])
						nics.append({'addr':addr, 'netmask':netmask, 'broadcast':broadcast, 'mac':ether['addr'], 'interface':interface})
		if(netifaces.AF_INET6 in ifaddrs):
			for ineta in ifaddrs[netifaces.AF_INET6]:
				if(ineta['addr'] == '::1'): continue
				if(ineta['addr'].startswith('fe80')): continue
				addr = ineta['addr']
				netmask = ineta['netmask'] if 'netmask' in ineta else '-'
				broadcast = ineta['broadcast'] if 'broadcast' in ineta else '-'
				if(not netifaces.AF_LINK in ifaddrs or len(ifaddrs[netifaces.AF_LINK]) == 0):
					nics.append({'addr':addr, 'netmask':netmask, 'broadcast':broadcast, 'mac':'-', 'interface':interface})
				else:
					for ether in ifaddrs[netifaces.AF_LINK]:
						mentionedMacs.append(ether['addr'])
						nics.append({'addr':addr, 'netmask':netmask, 'broadcast':broadcast, 'mac':ether['addr'], 'interface':interface})
		if(netifaces.AF_LINK in ifaddrs):
			for ether in ifaddrs[netifaces.AF_LINK]:
				if(ether['addr'].strip() == ''): continue
				if(ether['addr'].startswith('00:00:00:00:00:00')): continue
				if(not ether['addr'] in mentionedMacs):
					nics.append({'addr':'-', 'netmask':'-', 'broadcast':'-', 'mac':ether['addr'], 'interface':interface})
	return nics

def getOs():
	if 'win32' in OS_TYPE:
		try:
			return f"Windows {platform.win32_ver()[0]} {platform.win32_edition()}"
		except Error:
			return platform.system()
	elif 'linux' in OS_TYPE:
		return distro.name()
	elif 'darwin' in OS_TYPE:
		return 'macOS'

def getOsVersion():
	if 'win32' in OS_TYPE:
		return platform.win32_ver()[1]
	elif 'linux' in OS_TYPE:
		return distro.version()
	elif 'darwin' in OS_TYPE:
		return platform.mac_ver()[0]

def getUptime():
	return time.time() - psutil.boot_time()

def getKernelVersion():
	if 'win32' in OS_TYPE:
		return '-'
	elif 'linux' in OS_TYPE or 'darwin' in OS_TYPE:
		return platform.release()

def getMachineUid():
	uid = ''
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_ComputerSystemProduct(): uid = o.UUID
	elif 'linux' in OS_TYPE:
		command = 'dmidecode -s system-uuid'
		uid = os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')
	elif 'darwin' in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'"
		uid = os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')
	if uid.strip() == '': uid = getHostname() # fallback
	return uid

def getMachineSerial():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.SerialNumber
	elif 'linux' in OS_TYPE:
		command = 'dmidecode -s system-serial-number'
	elif 'darwin' in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformSerialNumber/{print $(NF-1)}'"
	return os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')

def getMachineManufacturer():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.Manufacturer
	elif 'linux' in OS_TYPE:
		command = 'dmidecode -s system-manufacturer'
	elif 'darwin' in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/manufacturer/{print $(NF-1)}'"
	return os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')

def getMachineModel():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Computersystem(): return o.Model
	elif 'linux' in OS_TYPE:
		command = 'dmidecode -s system-product-name'
	elif 'darwin' in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/model/{print $(NF-1)}'"
	return os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')

def getBiosVersion():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Bios(): return o.Version
	elif 'linux' in OS_TYPE:
		command = 'dmidecode -s bios-version'
	elif 'darwin' in OS_TYPE:
		command = "ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/version/{print $(NF-1)}'"
	return os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')

def getUefiOrBios():
	booted = '?'
	if 'win32' in OS_TYPE:
		command = 'bcdedit'
		res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
		if res.returncode == 0:
			booted = 'UEFI' if 'EFI' in guessEncodingAndDecode(res.stdout) else 'Legacy'
	elif 'linux' in OS_TYPE:
		booted = 'UEFI' if os.path.exists('/sys/firmware/efi') else 'Legacy'
	elif 'darwin' in OS_TYPE:
		booted = 'UEFI'
	return booted

def getSecureBootEnabled():
	secureboot = '?'
	if 'win32' in OS_TYPE:
		try:
			registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 0, winreg.KEY_READ)
			value, regtype = winreg.QueryValueEx(registry_key, 'UEFISecureBootEnabled')
			winreg.CloseKey(registry_key)
			return str(value)
		except WindowsError: return '0'
	elif 'linux' in OS_TYPE:
		command = 'mokutil --sb-state'
		secureboot = '1' if 'enabled' in os.popen(command).read().replace('\t','').replace(' ','') else '0'
	return secureboot

def queryAppxPackages():
	packages = []
	try:
		# this silently fails under Windows 7 and older since there is no Get-AppxPackage cmdlet and no AppX packages at all
		result = subprocess.run(['powershell.exe', '-executionpolicy', 'bypass', '-command', 'Get-AppxPackage -allusers | select Name, Version, Publisher, PackageUserInformation | ConvertTo-Json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
		resultDecoded = json.loads(result.stdout)
		for package in resultDecoded:
			packages.append({
				'name': '[AppX] '+package['Name'],
				'version': package['Version'],
				'description': package['Publisher']
			})
	except Exception as e: pass
	return packages
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
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key+'\\'+name, 0, winreg.KEY_READ)
			displayName, regtype = winreg.QueryValueEx(reg, 'DisplayName')
			displayVersion = ''
			displayPublisher = ''
			systemComponent = 0
			try: displayVersion, regtype = winreg.QueryValueEx(reg, 'DisplayVersion')
			except WindowsError: pass
			try: displayPublisher, regtype = winreg.QueryValueEx(reg, 'Publisher')
			except WindowsError: pass
			try: systemComponent, regtype = winreg.QueryValueEx(reg, 'SystemComponent')
			except WindowsError: pass
			winreg.CloseKey(reg)
			if(displayName.strip() == '' or systemComponent == 1): continue
			software.append({
				'name': displayName,
				'version': displayVersion,
				'description': displayPublisher
			})
		except WindowsError: pass
	return software
def getInstalledSoftware():
	software = []
	if 'win32' in OS_TYPE:
		x64software = queryRegistrySoftware('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
		x32software = queryRegistrySoftware('SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
		appXpackages = queryAppxPackages()
		software = x32software + x64software + appXpackages
	elif 'linux' in OS_TYPE:
		command = 'apt list --installed'
		for l in os.popen(command).read().split('\n'):
			packageName = l.split('/')[0]
			if(len(l.split(' ')) > 1):
				packageVersion = l.split(' ')[1];
				if(packageName != '' and packageVersion != ''):
					software.append({
						'name': packageName,
						'version': packageVersion,
						'description': ''
					})
	elif 'darwin' in OS_TYPE:
		appdirname = '/Applications'
		appdir = os.fsencode(appdirname)
		for app in os.listdir(appdir):
			appname = os.fsdecode(app)
			if(not os.path.isfile(appname) and appname.endswith('.app')):
				infoPlstPath = os.path.join(appdirname, appname, 'Contents', 'Info.plist')
				if(not os.path.isfile(infoPlstPath)): continue
				with open(infoPlstPath, 'rb') as f:
					try:
						plist_data = plistlib.load(f)
						software.append({
							'name': plist_data.get('CFBundleName') or appname,
							'version': plist_data.get('CFBundleVersion') or '?',
							'description': plist_data.get('CFBundleGetInfoString') or '-'
						})
					except ValueError:
						logger('Error parsing Info.plist of application:', infoPlstPath)
	return software

def getIsActivated():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.SoftwareLicensingProduct():
			if(o.ApplicationID == '55c92734-d682-4d71-983e-d6ec3f16059f'):
				#print(o.Name)
				#print(o.Description)
				if(o.LicenseStatus == 1): return '1'
		return '0'
	else: return '-'

def getLocale():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_OperatingSystem():
			return o.Locale
		return '?'
	elif 'darwin' in OS_TYPE:
		try:
			command = 'osascript -e "user locale of (get system info)"'
			return os.popen(command).read().strip()
		except Exception as e: logger(e)
	else: return '-'

def getCpu():
	if 'win32' in OS_TYPE:
		return platform.processor()
	elif 'linux' in OS_TYPE:
		command = 'cat /proc/cpuinfo | grep "model name" | uniq'
		return os.popen(command).read().split(':', 1)[1].strip()
	elif 'darwin' in OS_TYPE:
		command = 'sysctl -n machdep.cpu.brand_string'
		return os.popen(command).read().strip()

def getGpu():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_VideoController(): return o.Name
		return '?'
	elif 'linux' in OS_TYPE:
		return '?'
	elif 'darwin' in OS_TYPE:
		try:
			command = 'system_profiler SPDisplaysDataType -json'
			jsonstring = os.popen(command).read().strip()
			jsondata = json.loads(jsonstring)
			for gpu in jsondata['SPDisplaysDataType']:
				return gpu['sppci_model']
		except Exception as e: return '?'

def getLinuxXAuthority():
	try:
		# LightDM
		for i in range(10):
			checkFile = '/var/run/lightdm/root/:'+str(i)
			if(os.path.exists(checkFile)):
				return {'file':checkFile, 'display':':'+str(i)}
		# GDM
		command = "who|grep -E '\(:[0-9](\.[0-9])*\)'|awk '{print $1$NF}'|sort -u"
		for l in os.popen(command).read().split('\n'):
			if(l.strip() == ''): continue
			display = l.split('(')[1].split(')')[0]
			username = l.split('(')[0]
			userid = os.popen('id -u '+shlex.quote(username)).read().strip()
			checkFile = '/run/user/'+str(int(userid))+'/gdm/Xauthority'
			if(os.path.exists(checkFile)):
				return {'file':checkFile, 'display':display}
	except Exception as e:
		logger('Unable to get X authority:', e)
	return None
def getScreens():
	screens = []
	if 'win32' in OS_TYPE:
		try:
			objWMI = GetObject(r'winmgmts:\\.\root\WMI').InstancesOf('WmiMonitorID')
			for monitor in objWMI:
				try:
					devPath = monitor.InstanceName.split('_')[0]
					regPath = f'SYSTEM\\CurrentControlSet\\Enum\\{devPath}\\Device Parameters'
					registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, regPath, 0, winreg.KEY_READ)
					edid, regtype = winreg.QueryValueEx(registry_key, 'EDID')
					winreg.CloseKey(registry_key)
					if not edid: continue
					#print ('DEBUG: EDID Version: '+str(edid[18])+'.'+str(edid[19]))
					#dtd = 54  # start byte of detailed timing desc.
					# upper nibble of byte x 2^8 combined with full byte
					#hres = ((edid[dtd+4] >> 4) << 8) | edid[dtd+2]
					#vres = ((edid[dtd+7] >> 4) << 8) | edid[dtd+5]
					edidp = pyedid.parse_edid(edid)
					manufacturer = edidp.manufacturer or 'Unknown'
					if(manufacturer == 'Unknown'): manufacturer += ' ('+str(edidp.manufacturer_id)+')'
					screens.append({
						'name': edidp.name,
						'manufacturer': manufacturer,
						'manufactured': str(edidp.year or '-'),
						'resolution': str(edidp.resolutions[-1][0])+' x '+str(edidp.resolutions[-1][1]) if edidp.resolutions else '-',
						'size': str(edidp.width)+' x '+str(edidp.height),
						'type': str(edidp.product_id or '-'),
						'serialno': edidp.serial or '-',
						'technology': str(edidp.type or '-')
					})
				except Exception as e: logger('Unable to get screen details:', e)
		except Exception as e: logger('Unable to get attached screens:', e)
	elif 'linux' in OS_TYPE:
		try:
			xAuthority = getLinuxXAuthority()
			if(xAuthority != None):
				os.environ['XAUTHORITY'] = xAuthority['file']
				os.environ['DISPLAY'] = xAuthority['display']
			randr = subprocess.check_output(['xrandr', '--verbose'])
			for edid in pyedid.get_edid_from_xrandr_verbose(randr):
				try:
					edidp = pyedid.parse_edid(edid)
					manufacturer = edidp.manufacturer or 'Unknown'
					if(manufacturer == 'Unknown'): manufacturer += ' ('+str(edidp.manufacturer_id)+')'
					screens.append({
						'name': edidp.name,
						'manufacturer': manufacturer,
						'manufactured': str(edidp.year or '-'),
						'resolution': str(edidp.resolutions[-1][0])+' x '+str(edidp.resolutions[-1][1]) if edidp.resolutions else '-',
						'size': str(edidp.width)+' x '+str(edidp.height),
						'type': str(edidp.product_id or '-'),
						'serialno': edidp.serial or '-',
						'technology': str(edidp.type or '-')
					})
				except Exception as e: logger('Unable to get screen details:', e)
		except Exception as e: logger('Unable to get attached screens:', e)
	elif 'darwin' in OS_TYPE:
		try:
			command = 'system_profiler SPDisplaysDataType -json'
			jsonstring = os.popen(command).read().strip()
			jsondata = json.loads(jsonstring)
			for gpu in jsondata['SPDisplaysDataType']:
				for screen in gpu['spdisplays_ndrvs']:
					try:
						edidp = pyedid.parse_edid(screen['_spdisplays_edid'].replace('0x',''))
						manufacturer = edidp.manufacturer or 'Unknown'
						resolution = '-' # MacBook internal screens do not provide resolution data :'(
						if(manufacturer == 'Unknown'): manufacturer += ' ('+str(edidp.manufacturer_id)+')'
						if(len(edidp.resolutions) > 0): resolution = str(edidp.resolutions[-1][0])+' x '+str(edidp.resolutions[-1][1])
						screens.append({
							'name': edidp.name,
							'manufacturer': manufacturer,
							'manufactured': str(edidp.year or '-'),
							'resolution': resolution,
							'size': str(edidp.width)+' x '+str(edidp.height),
							'type': str(edidp.product_id or '-'),
							'serialno': edidp.serial or '-',
							'technology': str(edidp.type or '-')
						})
					except Exception as e: logger('Unable to get screen details:', e)
		except Exception as e: logger('Unable to get attached screens:', e)
	return screens

def winPrinterStatus(status, state):
	if(state == 2): return 'Error'
	if(state == 8): return 'Paper Jam'
	if(state == 16): return 'Out Of Paper'
	if(state == 64): return 'Paper Problem'
	if(state == 131072): return 'Toner Low'
	if(state == 262144): return 'No Toner'
	if(status == 1): return 'Other'
	if(status == 3): return 'Idle'
	if(status == 4): return 'Printing'
	if(status == 5): return 'Warmup'
	if(status == 6): return 'Stopped'
	if(status == 7): return 'Offline'
	return 'Unknown'
def getPrinters():
	printers = []
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for o in w.Win32_Printer():
			printers.append({
				'name': o.Name,
				'driver': o.DriverName,
				'paper': '' if o.PrinterPaperNames == None else ', '.join(o.PrinterPaperNames),
				'dpi': o.HorizontalResolution,
				'uri': o.PortName,
				'status': winPrinterStatus(o.PrinterStatus, o.PrinterState)
			})
	elif 'linux' in OS_TYPE or 'darwin' in OS_TYPE:
		CUPS_CONFIG = '/etc/cups/printers.conf'
		if(not os.path.exists(CUPS_CONFIG)): return printers
		with open(CUPS_CONFIG, 'r', encoding='utf-8', errors='replace') as file:
			printer = {'name': '', 'driver': '', 'paper': '', 'dpi': '', 'uri': '', 'status': ''}
			for line in file:
				l = line.rstrip('\n')
				if(l.startswith('<DefaultPrinter ') or l.startswith('<Printer ')):
					printer = {
						'name': l.split(' ', 1)[1].rstrip('>'),
						'driver': '', 'paper': '', 'dpi': '', 'uri': '', 'status': ''
					}
				if(l.startswith('MakeModel ')):
					printer['driver'] = l.split(' ', 1)[1]
				if(l.startswith('DeviceURI ')):
					printer['uri'] = l.split(' ', 1)[1]
				if(l.startswith('</DefaultPrinter>') or l.startswith('</Printer>')):
					if(printer['name'] != ''): printers.append(printer)
	return printers

def getPartitions():
	partitions = []
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
		for ld in w.Win32_LogicalDisk():
			devicePath = '?'
			for v in w.Win32_Volume():
				if(v.DriveLetter == ld.DeviceID):
					devicePath = v.DeviceID
			partitions.append({
				'device': devicePath,
				'mountpoint': ld.DeviceID,
				'filesystem': ld.FileSystem,
				'name': ld.VolumeName,
				'size': ld.Size,
				'free': ld.FreeSpace,
				'serial': ld.VolumeSerialNumber
			})
	elif 'linux' in OS_TYPE:
		command = 'df -k --output=used,avail,fstype,source,target'
		lines = os.popen(command).read().strip().splitlines()
		first = True
		for line in lines:
			if(first): first = False; continue
			values = ' '.join(line.split()).split()
			if(len(values) != 5): continue
			if(values[2] == 'tmpfs' or values[2] == 'devtmpfs'): continue
			partitions.append({
				'device': values[3],
				'mountpoint': values[4],
				'filesystem': values[2],
				'size': (int(values[0])+int(values[1]))*1024,
				'free': int(values[1])*1024,
				'name': '',
				'serial': ''
			})
	elif 'darwin' in OS_TYPE:
		command = 'df -k'
		lines = os.popen(command).read().strip().splitlines()
		first = True
		for line in lines:
			if(first): first = False; continue
			values = ' '.join(line.split()).split()
			if(len(values) != 9): continue
			if(values[0] == 'devfs'): continue
			partitions.append({
				'device': values[0],
				'mountpoint': values[8],
				'filesystem': '',
				'size': (int(values[2])+int(values[3]))*1024,
				'free': int(values[3])*1024,
				'name': '',
				'serial': ''
			})
	return partitions

def getLogins(since):
	logins = []
	try:
		# server's `since` value is in UTC
		dateObjectSince = datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
		if 'win32' in OS_TYPE:
			logins = getLoginsWindows(dateObjectSince, config['windows']['username-with-domain'])
		elif 'linux' in OS_TYPE:
			logins = getLoginsLinux(dateObjectSince)
		elif 'darwin' in OS_TYPE:
			logins = getLoginsMac(dateObjectSince)
	except Exception as e:
		logger('Error reading logins:', e)
	return logins

def getEvents(log, query, since):
	maxBatch = 10000
	events = []
	try:
		dateObjectSince = datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S')
		if 'win32' in OS_TYPE:
			events = getEventsWindows(log, query, dateObjectSince, maxBatch, debug=config['debug'])
		elif 'linux' in OS_TYPE and log == 'journalctl':
			events = getEventsLinux(log, query, dateObjectSince, maxBatch, debug=config['debug'])
	except Exception as e:
		logger('Error reading events:', e)
	return events

def getServiceStatus():
	services = []
	if not os.path.exists(SERVICE_CHECKS_PATH): return
	for file in [f for f in os.listdir(SERVICE_CHECKS_PATH) if os.path.isfile(os.path.join(SERVICE_CHECKS_PATH, f))]:
		serviceScriptPath = os.path.join(SERVICE_CHECKS_PATH, file)
		startTime = time.time()
		logger('Executing service check script '+serviceScriptPath+'...')
		res = subprocess.run(serviceScriptPath, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
		# example output (CheckMK format): 0 "My service" myvalue=73;80;90 My output text
		# https://docs.checkmk.com/latest/de/localchecks.html
		for line in guessEncodingAndDecode(res.stdout).splitlines():
			values = shlex.split(line)
			if(len(values) < 4):
				print('  invalid output from script: '+line)
				continue
			services.append({'status':values[0], 'name':values[1], 'merics':values[2], 'details':' '.join(values[3:])})
		if(config['debug']): print('  took '+str(time.time()-startTime))
	return services


##### AGENT-SERVER COMMUNICATION FUNCTIONS #####
JOB_STATE_ERROR       = -1
JOB_STATE_DOWNLOADING = 1
JOB_STATE_EXECUTING   = 2
JOB_STATE_FINISHED    = 3

def downloadFile(url, params, path, jobId):
	with requests.get(url, params=params, stream=True, timeout=(config['connection-timeout'],config['read-timeout'])) as r:
		r.raise_for_status()
		totalLength = r.headers.get('content-length')
		if(totalLength): totalLength = int(totalLength)
		with open(path, 'wb') as f:
			bytesWritten = 0
			reportCounter = 0
			for chunk in r.iter_content(chunk_size=config['chunk-size']): 
				f.write(chunk)
				bytesWritten += config['chunk-size']
				if(totalLength):
					reportCounter += 1
					if(reportCounter > config['report-frames']):
						reportCounter = 0
						jsonRequest('oco.agent.update_job_state', {
							'job-id': jobId,
							'state': JOB_STATE_DOWNLOADING,
							'return-code': None,
							'download-progress': 100 * bytesWritten / totalLength,
							'message': ''
						})

def jsonRequest(method, data):
	headers = {'content-type': 'application/json'}
	data = {
		'jsonrpc': '2.0',
		'id': 1,
		'method': method,
		'params': {
			'uid': config['machine-uid'],
			'hostname': getHostname(),
			'agent-key': config['agent-key'],
			'data': data
		}
	}
	data_json = json.dumps(data)

	try:
		# send request
		if(config['debug']): logger('< ' + data_json)
		response = requests.post(config['api-url'], data=data_json, headers=headers, timeout=(config['connection-timeout'],config['read-timeout']))

		# print response
		if(config['debug']): logger('> (' + str(response.elapsed.total_seconds()) + 's) [' + str(response.status_code) + '] ' + response.text)
		if(response.status_code != 200):
			logger('Request failed with HTTP status code ' + str(response.status_code))

		# return response
		return response

	except Exception as e:
		logger(e)
		return None


##### VARIOUS AGENT FUNCTIONS #####

def isUserLoggedIn():
	if 'win32' in OS_TYPE:
		w=wmi.WMI()
		for u in w.Win32_Process(Name='explorer.exe'):
			return True
	elif 'linux' in OS_TYPE:
		command = 'who'
		entries = os.popen(command).read().split('\n')
		for entry in entries:
			if(entry.strip() != ''):
				return True
	elif 'darwin' in OS_TYPE:
		return True # not implemented
	return False

def removeAll(path):
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			os.remove(os.path.join(root, name))
		for name in dirs:
			os.rmdir(os.path.join(root, name))
	os.rmdir(path)

def guessEncodingAndDecode(textBytes, codecs=['utf-8', 'cp1252', 'cp850']):
	for codec in codecs:
		try:
			return textBytes.decode(codec)
		except UnicodeDecodeError: pass
	return textBytes.decode(sys.stdout.encoding, 'replace') # fallback: replace invalid characters

def jobOutputReporter(jobId):
	delay = config['report-job-output']
	if(not delay): return # no periodical reporting
	lastOutput = b''
	currentThread = threading.currentThread()
	currentThread.endEvent.wait(delay)
	while not currentThread.endEvent.is_set():
		currentOutput = getattr(currentThread, 'output', b'')
		if(lastOutput != currentOutput):
			jsonRequest('oco.agent.update_job_state', {
					'job-id': jobId, 'state': JOB_STATE_EXECUTING, 'return-code': None, 'message': guessEncodingAndDecode(currentOutput)
				})
		lastOutput = currentOutput
		currentThread.endEvent.wait(delay)

# function for checking if agent is already running (e.g. due to long running software jobs)
def lockCheck():
	try:
		# if we can open the lockfile without error, no other instance is running
		with open(LOCKFILE_PATH, 'x') as lockfile:
			pid = str(os.getpid())
			lockfile.write(pid)
			logger('OCO Agent starting with lock file (pid '+pid+')...')
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
					if('oco' in p.exe() or 'python' in p.exe()): alreadyRunning = True
			except Exception: pass
			if(alreadyRunning):
				# another instance is still running -> exit
				logger('OCO Agent already running at pid '+str(oldpid)+' (lock file '+LOCKFILE_PATH+'). Exiting.')
				sys.exit()
			else:
				# process is not running anymore -> delete lockfile and start agent
				logger('Cleaning up orphaned lock file (pid '+str(oldpid)+' is not running anymore) and starting OCO Agent...')
				os.unlink(LOCKFILE_PATH)
				with open(LOCKFILE_PATH, 'x') as lockfile:
					pid = str(os.getpid())
					lockfile.write(pid)
					logger('OCO Agent starting with lock file (pid '+pid+')...')
	atexit.register(lockClean, lockfile)
# clean up lockfile
def lockClean(lockfile):
	lockfile.close()
	os.unlink(LOCKFILE_PATH)
	logger('Closing lock file and exiting.')


##### AGENT MAIN LOOP #####

def daemon(args):
	global exitEvent
	while not exitEvent.is_set():
		try:
			mainloop(args)
		except KeyError as e:
			logger('KeyError:', e)
		logger('Running in daemon mode. Waiting '+str(config['query-interval'])+' seconds to send next request.')
		exitEvent.wait(config['query-interval'])

# the main server communication function
# sends a "agent_hello" packet to the server and then executes various tasks, depending on the server's response
def mainloop(args):
	global restartFlag, configParser

	# send initial request
	logger('Sending agent_hello...')
	request = jsonRequest('oco.agent.hello', {
		'agent_version': __version__,
		'networks': getNics(),
		'services': getServiceStatus(),
		'uptime': getUptime()
	})

	# check response
	if(request != None and request.status_code == 200):
		responseJson = request.json()

		# save server key if server key is not already set in local config
		if(config['server-key'] == None or config['server-key'] == ''):
			logger('Write new config with updated server key...')
			if(not configParser.has_section('server')): configParser.add_section('server')
			configParser.set('server', 'server-key', responseJson['result']['params']['server-key'])
			with open(args.config, 'w') as fileHandle: configParser.write(fileHandle)
			config['server-key'] = configParser.get('server', 'server-key')

		# check server key
		if(config['server-key'] != responseJson['result']['params']['server-key']):
			logger('!!! Invalid server key, abort.')
			return

		# update agent key if requested
		if(responseJson['result']['params']['agent-key'] != None):
			logger('Write new config with updated agent key...')
			if(not configParser.has_section('agent')): configParser.add_section('agent')
			configParser.set('agent', 'agent-key', responseJson['result']['params']['agent-key'])
			with open(args.config, 'w') as fileHandle: configParser.write(fileHandle)
			config['agent-key'] = configParser.get('agent', 'agent-key')

		# send computer info if requested
		loginsSince = '2000-01-01 00:00:00'
		if('logins-since' in responseJson['result']['params']):
			loginsSince = responseJson['result']['params']['logins-since']
		if(responseJson['result']['params']['update'] == 1):
			logger('Updating inventory data...')
			jsonRequest('oco.agent.update', {
				'hostname': getHostname(),
				'agent_version': __version__,
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
				'logins': getLogins(loginsSince),
			})

		# execute jobs if requested
		if(len(responseJson['result']['params']['software-jobs']) > 0):
			ignoreContainerIds = []
			for job in responseJson['result']['params']['software-jobs']:
				if('id' not in job or 'procedure' not in job):
					logger('Invalid job, skipping')
					continue
				if('container-id' in job and job['container-id'] in ignoreContainerIds):
					logger('Skipping Software Job '+str(job['id'])+' because container id '+str(job['container-id'])+' should be ignored.')
					continue
				if(job['procedure'].strip() == ''):
					logger('Software Job '+str(job['id'])+': prodecure is empty - do nothing but send success message to server.')
					jsonRequest('oco.agent.update_job_state', {
						'job-id': job['id'], 'state': JOB_STATE_FINISHED, 'return-code': 0, 'message': ''
					})
					continue
				if(restartFlag == True):
					logger('Skipping Software Job '+str(job['id'])+' because restart flag is set.')
					continue

				try:

					# create temp dir
					logger('Begin Software Job '+str(job['id']))
					tempZipPath = tempfile.gettempdir()+'/oco-staging.zip'
					tempPath = tempfile.gettempdir()+'/oco-staging'
					if(os.path.exists(tempPath)): removeAll(tempPath)
					os.mkdir(tempPath)

					# download if needed
					if(job['download'] == True):
						logger('Downloading into '+tempZipPath+'...')
						jsonRequest('oco.agent.update_job_state', {
							'job-id': job['id'], 'state': JOB_STATE_DOWNLOADING, 'return-code': None, 'download-progress': 0, 'message': ''
						})
						downloadFile(
							config['api-url'],
							{'uid': config['machine-uid'], 'hostname': getHostname(), 'agent-key': config['agent-key'], 'id': job['package-id']},
							tempZipPath,
							job['id']
						)
						jsonRequest('oco.agent.update_job_state', {
							'job-id': job['id'], 'state': JOB_STATE_DOWNLOADING, 'return-code': None, 'download-progress': 101, 'message': ''
						})
						with ZipFile(tempZipPath, 'r') as zipObj:
							logger('Unzipping into '+tempPath+'...')
							zipObj.extractall(tempPath)

					# change to tmp dir
					logger('Executing: '+job['procedure']+'...')
					jsonRequest('oco.agent.update_job_state', {
						'job-id': job['id'], 'state': JOB_STATE_EXECUTING, 'return-code': None, 'download-progress': 100, 'message': ''
					})
					os.chdir(tempPath)

					# restore library search path for subprocess (modified by PyInstaller)
					# causes problems e.g. with `apt` or the Windows upgrade `setup.exe` not finding its libaries
					# see https://pyinstaller.org/en/v6.9.0/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application
					sub_env = os.environ.copy()
					if('LD_LIBRARY_PATH_ORIG' in sub_env):
						sub_env['LD_LIBRARY_PATH'] = sub_env['LD_LIBRARY_PATH_ORIG']
					elif('LD_LIBRARY_PATH' in sub_env):
						del sub_env['LD_LIBRARY_PATH']
					if(sys.platform == 'win32'):
						ctypes.windll.kernel32.SetDllDirectoryW(None)

					# execute procedure
					proc = subprocess.Popen(
						job['procedure'], shell=True, env=sub_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL
					)
					jobOutputReportThread = threading.Thread(target=jobOutputReporter, args=(job['id'],))
					jobOutputReportThread.endEvent = threading.Event()
					jobOutputReportThread.start()
					outBuffer = b''
					for line in iter(proc.stdout.readline, b''):
						outBuffer += line
						jobOutputReportThread.output = outBuffer
					proc.stdout.close()
					jobOutputReportThread.endEvent.set()
					jobStatusRequest = jsonRequest('oco.agent.update_job_state', {
						'job-id': job['id'], 'state': JOB_STATE_FINISHED, 'return-code': proc.wait(), 'message': guessEncodingAndDecode(outBuffer)
					})

					# check server's update_job_state response
					# cancel pending jobs if sequence mode is 1 (= 'abort after failed') and job failed
					if('container-id' in job and 'sequence-mode' in job and job['sequence-mode'] == 1 and jobStatusRequest != None and jobStatusRequest.status_code == 200):
						jobStatusResponseJson = jobStatusRequest.json()
						jobSucceeded = True
						try:
							jobSucceeded = bool(jobStatusResponseJson['result']['params']['job-succeeded'])
						except KeyError: pass
						if(not jobSucceeded):
							logger('Add container id '+str(job['container-id'])+' to ignore array because server told me that the current job failed and sequence mode is set to 1.')
							ignoreContainerIds.append(job['container-id'])
							os.chdir(tempfile.gettempdir())
							continue

					# cleanup
					logger('Cleanup unpacked package files...')
					os.chdir(tempfile.gettempdir())
					removeAll(tempPath)

					# execute restart if requested
					if('restart' in job and job['restart'] != None and isinstance(job['restart'], int) and job['restart'] >= 0):
						timeout = 0
						if(isUserLoggedIn()): timeout = int(job['restart'])
						if 'win32' in OS_TYPE:
							res = subprocess.run('shutdown -r -t '+str(timeout*60), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True
						else:
							res = subprocess.run('shutdown -r +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True

					# execute shutdown if requested
					if('shutdown' in job and job['shutdown'] != None and isinstance(job['shutdown'], int) and job['shutdown'] >= 0):
						timeout = 0
						if(isUserLoggedIn()): timeout = int(job['shutdown'])
						if 'win32' in OS_TYPE:
							res = subprocess.run('shutdown -s -t '+str(timeout*60), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True
						else:
							res = subprocess.run('shutdown -h +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0): restartFlag = True

					# execute agent exit if requested (for agent update)
					if('exit' in job and job['exit'] != None and isinstance(job['exit'], int) and job['exit'] >= 0):
						logger('Agent Exit Requested. Bye...')
						if 'win32' in OS_TYPE:
							# restart service via scheduled task - if somebody has a better idea how to self-restart the service: contributions welcome!
							subprocess.run(['SCHTASKS', '/CREATE', '/F', '/RU', 'SYSTEM', '/SC', 'ONCE', '/ST', (datetime.datetime.now()+datetime.timedelta(minutes=1)).strftime("%H:%M"), '/TN', 'OCO Service Restart After Update', '/TR', 'cmd /c "net stop oco-agent & net start oco-agent"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
							time.sleep(61)
						sys.exit(0)

				except Exception as e:
					logger(e)
					jsonRequest('oco.agent.update_job_state', {
						'job-id': job['id'], 'state': JOB_STATE_ERROR, 'return-code': -9999, 'message': str(e)
					})
					os.chdir(tempfile.gettempdir())

		# send events from logs if requested
		if('events' in responseJson['result']['params']):
			events = []
			for eventQuery in responseJson['result']['params']['events']:
				if not 'log' in eventQuery or not 'query' in eventQuery or not 'since' in eventQuery: continue
				events += getEvents(eventQuery['log'], eventQuery['query'], eventQuery['since'])
			if(len(events) > 0):
				jsonRequest('oco.agent.events', {'events':events})

def signal_handler(signum, frame):
	global exitEvent
	exitEvent.set()

##### MAIN ENTRY POINT - AGENT INITIALIZATION #####
def main():
	try:
		# read arguments
		parser = argparse.ArgumentParser(add_help=False)
		parser.add_argument('--config', default=DEFAULT_CONFIG_PATH, type=str)
		parser.add_argument('--daemon', action='store_true')
		args = parser.parse_args()
		configFilePath = args.config
		logger('OCO Agent starting with config file: '+configFilePath+' ...')

		# read config
		configParser.read(configFilePath)
		if(configParser.has_section('agent')):
			config['debug'] = (int(configParser['agent'].get('debug', config['debug'])) == 1)
			config['hostname-remove-domain'] = (int(configParser['agent'].get('hostname-remove-domain', config['hostname-remove-domain'])) == 1)
			config['connection-timeout'] = int(configParser['agent'].get('connection-timeout', config['connection-timeout']))
			config['read-timeout'] = int(configParser['agent'].get('read-timeout', config['read-timeout']))
			config['query-interval'] = int(configParser['agent'].get('query-interval', config['query-interval']))
			config['chunk-size'] = int(configParser['agent'].get('chunk-size', config['chunk-size']))
			config['report-frames'] = int(configParser['agent'].get('report-frames', config['report-frames']))
			config['report-job-output'] = int(configParser['agent'].get('report-job-output', config['report-job-output']))
			config['agent-key'] = configParser['agent'].get('agent-key', config['agent-key'])
			config['machine-uid'] = configParser['agent'].get('machine-uid', getMachineUid())
		if(configParser.has_section('server')):
			config['api-url'] = configParser['server'].get('api-url', config['api-url'])
			config['server-key'] = configParser['server'].get('server-key', config['server-key'])
		if(configParser.has_section('windows')):
			config['windows']['username-with-domain'] = (int(configParser['windows'].get('username-with-domain', config['windows']['username-with-domain'])) == 1)

		# try server auto discovery
		if(config['api-url'].strip() == ''):
			logger('Server API URL is empty - trying DNS auto discovery ...')
			try:
				res = resolver.resolve(qname='_oco._tcp', rdtype=rdatatype.SRV, lifetime=10, search=True)
				for srv in res.rrset:
					config['api-url'] = 'https://'+str(srv.target)+':'+str(srv.port)+'/api-agent.php'
					logger('DNS auto discovery found server:', config['api-url'])
					if(not configParser.has_section('server')): configParser.add_section('server')
					configParser.set('server', 'api-url', config['api-url'])
					with open(configFilePath, 'w') as fileHandle: configParser.write(fileHandle)
					break
			except Exception as e:
				logger('DNS auto discovery failed:', e)

	except Exception as e:
		logger(e)
		sys.exit(1)

	# check if already running
	lockCheck()

	# handle the TERM/INT signal neatly - do not interrupt running software jobs
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGINT, signal_handler)

	# execute the agent as daemon if requested
	if(args.daemon):
		daemon(args)

	# execute the agent once
	else:
		try: mainloop(args)
		except KeyError as e:
			logger('KeyError:', e)
			sys.exit(1)

if __name__ == '__main__':
	main()
