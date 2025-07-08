#!/usr/bin/python3

import os
import pyedid
import subprocess
import shlex
import distro
import utmp
import datetime
import platform
import usb
import json
import glob
from shutil import which

from . import systemd, cups, local_users
from .. import base_inventory, logger


class Inventory(base_inventory.BaseInventory):
	SERVICE_CHECKS_PATH = '/usr/lib/oco-agent/service-checks'

	def __init__(self, config):
		super(Inventory, self).__init__(config)

	def __getXAuthority(self):
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

	def getInstalledSoftware(self):
		software = []
		if(which('apt')):
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
		else:
			logger('No supported package manager found - unable to query installed software')
		return software

	def __querySssdUserGuid(self, uid):
		try:
			# this module is only available when the Debian/Ubuntu package python3-ldb is installed
			# it's OK if the import fails, then this feature is not available
			import ldb
			for f in glob.glob('/var/lib/sss/db/cache_*.ldb'):
				db = ldb.Ldb()
				db.connect(f, ldb.FLG_RDONLY)
				for result in db.search(expression=f'uidNumber={uid}'):
					return str(result['uniqueID']).strip()
		except Exception as e:
			logger('Error getting GUID for user:', uid, e)
		return None

	def getLogins(self, dateObjectSince):
		users = []
		guidCache = {}
		try:
			with open('/var/log/wtmp', 'rb') as fd:
				buf = fd.read()
				for entry in utmp.read(buf):
					if(str(entry.type) == 'UTmpRecordType.user_process'):
						dateObject = datetime.datetime.utcfromtimestamp(entry.sec).replace(tzinfo=datetime.timezone.utc) # utmp values are in UTC
						if(dateObject <= dateObjectSince): continue
						if(entry.user in guidCache):
							guid = guidCache[entry.user]
						else:
							uid = os.popen('id -u '+shlex.quote(entry.user)).read().strip()
							guid = self.__querySssdUserGuid(uid)
							guidCache[entry.user] = guid
						users.append({
							'guid': guid,
							'display_name': os.popen('getent passwd '+shlex.quote(entry.user)+' | cut -d : -f 5').read().strip().rstrip(','),
							'username': entry.user,
							'console': entry.line,
							'timestamp': dateObject.strftime('%Y-%m-%d %H:%M:%S')
						})
		except Exception as e:
			logger('Error reading logins:', e)
		return users

	def getEvents(self, log, query, dateObjectSince):
		# errors are handled in oco_agent.py
		maxBatch = 10000
		if log == 'journalctl':
			return systemd.getEvents(query, dateObjectSince, maxBatch, debug=self.config['debug'])
		else:
			raise Exception('Log "'+str(log)+'" not supported!')

	def getSecureBootEnabled(self):
		command = 'mokutil --sb-state'
		return '1' if 'enabled' in os.popen(command).read().replace('\t','').replace(' ','') else '0'

	def getScreens(self):
		screens = []
		try:
			xAuthority = self.__getXAuthority()
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
				except Exception as e:
					logger('Unable to get screen details:', e)
		except Exception as e:
			logger('Unable to get attached screens:', e)
		return screens

	def getMachineUid(self):
		uid = self._execAndTrimOutput('dmidecode -s system-uuid')
		if uid.strip() == '': uid = self.getHostname() # fallback
		return uid

	def getMachineSerial(self):
		return self._execAndTrimOutput('dmidecode -s system-serial-number')

	def getMachineManufacturer(self):
		return self._execAndTrimOutput('dmidecode -s system-manufacturer')

	def getMachineModel(self):
		return self._execAndTrimOutput('dmidecode -s system-product-name')

	def getBiosVersion(self):
		return self._execAndTrimOutput('dmidecode -s bios-version')

	def getIsActivated(self):
		return '-'

	def getOs(self):
		return distro.name()

	def getOsVersion(self):
		return distro.version()

	def getLocale(self):
		return '-'

	def getKernelVersion(self):
		return platform.release()

	def getUefiOrBios(self):
		return 'UEFI' if os.path.exists('/sys/firmware/efi') else 'Legacy'

	def getCpu(self):
		command = 'cat /proc/cpuinfo | grep "model name" | uniq'
		return os.popen(command).read().split(':', 1)[1].strip()

	def getGpu(self):
		cards = []
		envpath = os.environ['PATH']
		os.environ['PATH'] = envpath + ':/usr/local/sbin:/usr/sbin:/sbin'
		command = 'lspci'
		for card in os.popen(command).read().strip().splitlines():
			for prefix in ['VGA compatible controller:', '3D controller:']:
				if prefix in card:
					cardName = card.split(prefix)[1].split('(rev')[0].strip()
					cards.append(cardName)
		os.environ['PATH'] = envpath
		return ', '.join(cards)

	def getPrinters(self):
		return cups.getPrinters()

	def _isInEncryptedBlkidChildren(self, mountpoint, children, contextEncrypted=False):
		for dct in children:
			if('mountpoints' not in dct or 'type' not in dct):
				return False
			if(mountpoint in dct['mountpoints']):
				return contextEncrypted or dct['type']=='crypt'
			elif('children' in dct):
				if(self._isInEncryptedBlkidChildren(mountpoint, dct['children'], dct['type']=='crypt')):
					return True
		return False

	def getPartitions(self):
		partitions = []
		devices = []

		# 1. get basic info (size, free space, fs type)
		command = 'df -k --output=used,avail,fstype,source,target'
		lines = os.popen(command).read().strip().splitlines()

		# 2. check if it is encrypted (= inside LUKS container)
		command = 'lsblk --json'
		tree = json.loads( os.popen(command).read().strip() )

		first = True
		for line in lines:
			if(first): first = False; continue
			values = ' '.join(line.split()).split()
			if(len(values) != 5): continue
			if(values[2] == 'tmpfs' or values[2] == 'devtmpfs'): continue

			if('blockdevices' in tree):
				isEncrypted = self._isInEncryptedBlkidChildren(values[4], tree['blockdevices'])

			# 3. get UUID + label
			command = 'blkid -s LABEL '+shlex.quote(values[3])
			line = os.popen(command).read().strip()
			index = line.rfind('=')
			label = line[index + 2:-1]
			command = 'blkid -s UUID '+shlex.quote(values[3])
			line = os.popen(command).read().strip()
			index = line.rfind('=')
			uuid = line[index + 2:-1]

			devices.append(values[3])
			partitions.append({
				'device': values[3],
				'mountpoint': values[4],
				'filesystem': values[2],
				'size': (int(values[0])+int(values[1]))*1024,
				'free': int(values[1])*1024,
				'name': label,
				'uuid': uuid,
				'encrypted': isEncrypted
			})

		return partitions

	def getUsbDevices(self):
		devices = []
		try:
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
		except Exception as e:
			logger('Error reading USB devices:', e)
		return devices

	def getLocalUsers(self):
		return local_users.getLocalUsers(
			self.config['linux']['local-users-min-uid'],
			self.config['linux']['local-users-max-uid']
		)
