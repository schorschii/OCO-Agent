#!/usr/bin/python3

import subprocess
import json
import pyedid
import time, datetime
import platform

import wmi, winreg
from win32com.client import GetObject
from winevt_ng import EventLog

from .. import base_inventory, logger, guessEncodingAndDecode


class Inventory(base_inventory.BaseInventory):
	def __init__(self, config):
		super(Inventory, self).__init__(config)

	def __queryAppxPackages(self):
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

	def __queryRegistrySoftware(self, key):
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

	def getInstalledSoftware(self):
		x64software = self.__queryRegistrySoftware('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
		x32software = self.__queryRegistrySoftware('SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
		appXpackages = self.__queryAppxPackages()
		return x32software + x64software + appXpackages

	def __queryRegistryUserDisplayName(self, querySid):
		# get user fullname from SessionData cache in registry
		try:
			key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\SessionData'
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
			count = 0
			while True:
				name = winreg.EnumKey(reg, count)
				count = count + 1
				reg2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key+'\\'+name, 0, winreg.KEY_READ)
				sid, regtype = winreg.QueryValueEx(reg2, 'LoggedOnUserSID')
				if querySid == sid:
					displayName, regtype = winreg.QueryValueEx(reg2, 'LoggedOnDisplayName')
					return displayName
		except WindowsError as e: pass
		return ''

	def __queryRegistryUserGuid(self, querySid):
		# get user GUID from ProfileList in registry
		try:
			key = f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{querySid}'
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
			guid, regtype = winreg.QueryValueEx(reg, 'Guid')
			return guid.strip('{}')
		except WindowsError as e: pass
		return None

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
	def getLogins(self, dateObjectSince):
		usernameWithDomain = self.config['windows']['username-with-domain']
		users = []
		try:
			query = EventLog.Query(
				'Security',
				"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[(EventData[Data[@Name='LogonType']='2'] or EventData[Data[@Name='LogonType']='10'] or EventData[Data[@Name='LogonType']='11']) and System[(EventID='4624')]]</Select></Query></QueryList>"
			)
			consolidatedEventList = []
			for event in query:
				eventDict = { 'TargetUserSid':'', 'TargetUserName':'', 'TargetDomainName':'', 'LogonType':'', 'IpAddress':'', 'LogonProcessName':'',
					'TimeCreated':event.System.TimeCreated['SystemTime'] }
				# put data of interest to dict
				for data in event.EventData.Data:
					if(data['Name'] in ['TargetUserSid', 'TargetUserName', 'TargetDomainName', 'LogonType', 'IpAddress', 'LogonProcessName']):
						eventDict[data['Name']] = data.cdata
				# eliminate duplicates and curious system logins
				if eventDict not in consolidatedEventList and eventDict['LogonProcessName'].strip() == 'User32':
					consolidatedEventList.append(eventDict)
			for event in consolidatedEventList:
				# example timestamp: 2021-04-09T13:47:14.719737700Z
				dateObject = datetime.datetime.strptime(event['TimeCreated'].split('.')[0], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc) # Windows event log timestamps are in UTC
				if(dateObject <= dateObjectSince): continue
				users.append({
					'guid': self.__queryRegistryUserGuid(event['TargetUserSid']),
					'display_name': self.__queryRegistryUserDisplayName(event['TargetUserSid']),
					'username': event['TargetDomainName']+'\\'+event['TargetUserName'] if usernameWithDomain else event['TargetUserName'],
					'console': event['IpAddress'],
					'timestamp': dateObject.strftime('%Y-%m-%d %H:%M:%S')
				})
		except Exception as e:
			logger('Error reading logins:', e)
		return users

	def getEvents(self, log, query, dateObjectSince):
		# errors are handled in oco_agent.py
		maxBatch = 10000

		foundEvents = []
		startTime = time.time()
		logger('Querying events from '+log+'...')

		query = EventLog.Query(log, query)
		for event in query:
			dateObject = datetime.datetime.strptime(event.System.TimeCreated['SystemTime'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
			if(dateObject <= dateObjectSince): continue
			eventDict = {
				'log': log,
				'provider': event.System.Provider['Name'],
				'event_id': event.EventID,
				'level': event.Level,
				'timestamp': dateObject.strftime('%Y-%m-%d %H:%M:%S'),
				'data': {}
			}
			if(hasattr(event, 'EventData')):
				for data in event.EventData.children:
					eventDict['data'][data['Name']] = str(data.cdata)
			foundEvents.append(eventDict)
			if(len(foundEvents) > maxBatch): break

		if(self.config['debug']):
			print('  took '+str(time.time()-startTime))

		return foundEvents

	def getSecureBootEnabled(self):
		try:
			registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 0, winreg.KEY_READ)
			value, regtype = winreg.QueryValueEx(registry_key, 'UEFISecureBootEnabled')
			winreg.CloseKey(registry_key)
			return str(value)
		except WindowsError as e:
			return '0'

	def getScreens(self):
		screens = []
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
				except Exception as e:
					logger('Unable to get screen details:', e)
		except Exception as e:
			logger('Unable to get attached screens:', e)
		return screens

	def getMachineUid(self):
		w = wmi.WMI()
		for o in w.Win32_ComputerSystemProduct():
			return o.UUID
		return self.getHostname() # fallback

	def getMachineSerial(self):
		w = wmi.WMI()
		for o in w.Win32_Bios():
			return o.SerialNumber

	def getMachineManufacturer(self):
		w = wmi.WMI()
		for o in w.Win32_Bios():
			return o.Manufacturer

	def getMachineModel(self):
		w = wmi.WMI()
		for o in w.Win32_Computersystem():
			return o.Model

	def getBiosVersion(self):
		w = wmi.WMI()
		for o in w.Win32_Bios():
			return o.Version

	def getIsActivated(self):
		w = wmi.WMI()
		for o in w.SoftwareLicensingProduct():
			if(o.ApplicationID == '55c92734-d682-4d71-983e-d6ec3f16059f'):
				#print(o.Name)
				#print(o.Description)
				if(o.LicenseStatus == 1): return '1'
		return '0'

	def getOs(self):
		try:
			return f"Windows {platform.win32_ver()[0]} {platform.win32_edition()}"
		except Error:
			return platform.system()

	def getOsVersion(self):
		return platform.win32_ver()[1]

	def getLocale(self):
		w = wmi.WMI()
		for o in w.Win32_OperatingSystem():
			return o.Locale
		return '?'

	def getKernelVersion(self):
		return '-'

	def getUefiOrBios(self):
		booted = '?'
		command = 'bcdedit'
		res = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
		if res.returncode == 0:
			booted = 'UEFI' if 'EFI' in guessEncodingAndDecode(res.stdout) else 'Legacy'
		return booted

	def getCpu(self):
		return platform.processor()

	def getGpu(self):
		w = wmi.WMI()
		for o in w.Win32_VideoController():
			return o.Name
		return '?'

	def __printerStatus(self, status, state):
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

	def getPrinters(self):
		printers = []
		w = wmi.WMI()
		for o in w.Win32_Printer():
			printers.append({
				'name': o.Name,
				'driver': o.DriverName,
				'paper': '' if o.PrinterPaperNames == None else ', '.join(o.PrinterPaperNames),
				'dpi': o.HorizontalResolution,
				'uri': o.PortName,
				'status': self.__printerStatus(o.PrinterStatus, o.PrinterState)
			})
		return printers

	def getPartitions(self):
		partitions = []
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
		return partitions
