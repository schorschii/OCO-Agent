#!/usr/bin/python3

import os, sys
import netifaces
import psutil
import time
import socket
import platform
import subprocess
import shlex

from . import logger, guessEncodingAndDecode


class BaseInventory:
	SERVICE_CHECKS_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))+'/service-checks'

	def __init__(self, config):
		self.config = config

	def _execAndTrimOutput(self, command):
		return os.popen(command).read().replace('\n','').replace('\t','').replace(' ','')

	def getHostname(self):
		hostname = socket.gethostname()
		if(self.config['hostname-remove-domain'] and '.' in hostname):
			hostname = hostname.split('.', 1)[0]
		return hostname

	def getDomain(self):
		return socket.getfqdn()

	def getArchitecture(self):
		return platform.machine()

	def getRam(self):
		return psutil.virtual_memory().total

	def getNics(self):
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

	def getUptime(self):
		return time.time() - psutil.boot_time()

	def getServiceStatus(self):
		services = []
		if not os.path.exists(self.SERVICE_CHECKS_PATH): return
		for file in [f for f in os.listdir(self.SERVICE_CHECKS_PATH) if os.path.isfile(os.path.join(self.SERVICE_CHECKS_PATH, f))]:
			serviceScriptPath = os.path.join(self.SERVICE_CHECKS_PATH, file)
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

			if(self.config['debug']):
				print('  took '+str(time.time()-startTime))

		return services
