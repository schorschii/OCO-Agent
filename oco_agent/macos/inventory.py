#!/usr/bin/python3

import os
import pyedid
import platform
import json
import plistlib
import usb

from . import utmpx
from ..linux import cups, local_users
from .. import base_inventory, logger


class Inventory(base_inventory.BaseInventory):
	def __init__(self, config):
		super(Inventory, self).__init__(config)

	def getInstalledSoftware(self):
		software = []
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

	def getLogins(self, dateObjectSince):
		return utmpx.getLogins(dateObjectSince)

	def getEvents(self, log, query, dateObjectSince):
		# errors are handled in oco_agent.py
		return [] # not implemented

	def getSecureBootEnabled(self):
		return '?'

	def getScreens(self):
		screens = []
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
					except Exception as e:
						logger('Unable to get screen details:', e)
		except Exception as e:
			logger('Unable to get attached screens:', e)
		return screens

	def getMachineUid(self):
		uid = self._execAndTrimOutput("ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'")
		if uid.strip() == '': uid = self.getHostname() # fallback
		return uid

	def getMachineSerial(self):
		return self._execAndTrimOutput("ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/IOPlatformSerialNumber/{print $(NF-1)}'")

	def getMachineManufacturer(self):
		return self._execAndTrimOutput("ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/manufacturer/{print $(NF-1)}'")

	def getMachineModel(self):
		return self._execAndTrimOutput("ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/model/{print $(NF-1)}'")

	def getBiosVersion(self):
		return self._execAndTrimOutput("ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\\" '/version/{print $(NF-1)}'")

	def getIsActivated(self):
		return '-'

	def getOs(self):
		return 'macOS'

	def getOsVersion(self):
		return platform.mac_ver()[0]

	def getLocale(self):
		try:
			command = 'osascript -e "user locale of (get system info)"'
			return os.popen(command).read().strip()
		except Exception as e:
			logger('Unable to get locale:', e)
			return '?'

	def getKernelVersion(self):
		return platform.release()

	def getUefiOrBios(self):
		return 'UEFI'

	def getCpu(self):
		command = 'sysctl -n machdep.cpu.brand_string'
		return os.popen(command).read().strip()

	def getGpu(self):
		try:
			command = 'system_profiler SPDisplaysDataType -json'
			jsonstring = os.popen(command).read().strip()
			jsondata = json.loads(jsonstring)
			for gpu in jsondata['SPDisplaysDataType']:
				return gpu['sppci_model']
		except Exception as e:
			logger('Unable to get GPU:', e)
			return '?'

	def getPrinters(self):
		return cups.getPrinters()

	def getPartitions(self):
		partitions = []
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

	def getUsbDevices(self):
		devices = []
		for dev in usb.core.find(find_all=True):
			try:
				devices.append({
					'subsystem': 'usb',
					'vendor': dev.idVendor,
					'product': dev.idProduct,
					'serial': usb.util.get_string(dev, dev.iSerialNumber),
					'name': usb.util.get_string(dev, dev.iProduct)
				})
			except Exception as e:
				logger('Error reading USB device:', e)
		return devices

	def getLocalUsers(self):
		return local_users.getLocalUsers(
			self.config['macos']['local-users-min-uid'],
			self.config['macos']['local-users-max-uid']
		)
