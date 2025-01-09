#!/usr/bin/python3

import os
import pyedid
import subprocess
import shlex
import distro
import utmp
import datetime
import platform

from . import systemd, cups
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
		return software

	def getLogins(self, dateObjectSince):
		users = []
		try:
			with open('/var/log/wtmp', 'rb') as fd:
				buf = fd.read()
				for entry in utmp.read(buf):
					if(str(entry.type) == 'UTmpRecordType.user_process'):
						dateObject = datetime.datetime.utcfromtimestamp(entry.sec).replace(tzinfo=datetime.timezone.utc) # utmp values are in UTC
						if(dateObject <= dateObjectSince): continue
						users.append({
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
		return '?' # not implemented

	def getPrinters(self):
		return cups.getPrinters()

	def getPartitions(self):
		partitions = []
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
		return partitions
