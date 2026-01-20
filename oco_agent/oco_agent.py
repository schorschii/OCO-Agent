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
import os, sys
import configparser
import argparse
import atexit
import psutil
import time
import datetime
import tempfile
import subprocess
import hmac, hashlib
import base64
import traceback
from shutil import which
from zipfile import ZipFile
from dns import resolver, rdatatype
from Crypto.Cipher import AES
from Crypto import Random

from . import __version__, logger, guessEncodingAndDecode

##### CONSTANTS #####

OS_TYPE             = sys.platform.lower()
EXECUTABLE_PATH     = os.path.abspath(os.path.dirname(sys.argv[0]))
DEFAULT_CONFIG_PATH = EXECUTABLE_PATH+'/oco-agent.ini'
DEFAULT_TSTAMP_PATH = EXECUTABLE_PATH+'/oco-agent.timestamp'
LOCKFILE_PATH       = tempfile.gettempdir()+'/oco-agent.lock'

if 'linux' in OS_TYPE or 'darwin' in OS_TYPE:
	DEFAULT_TSTAMP_PATH = '/var/lib/oco-agent/oco-agent.timestamp'
if 'linux' in OS_TYPE:
	DEFAULT_CONFIG_PATH = '/etc/oco-agent.ini'


##### OS SPECIFIC IMPORTS #####

if 'win32' in OS_TYPE:
	import wmi, ctypes
	from .windows import inventory, password_rotation
	from .windows.policy_deployment import PolicyDeployment

elif 'linux' in OS_TYPE:
	from .linux import inventory, password_rotation
	from .base_policy_deployment import BasePolicyDeployment as PolicyDeployment

elif 'darwin' in OS_TYPE:
	from .macos import inventory, password_rotation
	from .macos.policy_deployment import PolicyDeployment
	# set OpenSSL path to macOS defaults
	# (Github Runner sets this to /usr/local/etc/openssl@1.1/ which does not exist in plain macOS installations)
	os.environ['SSL_CERT_FILE'] = '/private/etc/ssl/cert.pem'
	os.environ['SSL_CERT_DIR']  = '/private/etc/ssl/certs'
	# system CA certs debugging
	#import ssl; print(ssl.get_default_verify_paths())
	#ctx = ssl.SSLContext(); ctx.load_default_certs(); print(ctx.get_ca_certs())


##### GLOBAL VARIABLES #####

exitEvent = threading.Event()
forceUpdateFlag = False
restartFlag = False
serverTimestamp = 0
configFilePath = None
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
	'linux': {
		'local-users-min-uid': 1000,
		'local-users-max-uid': 65534
	},
	'macos': {
		'local-users-min-uid': 1000,
		'local-users-max-uid': 65534
	},
	'windows': {
		'username-with-domain': False
	},
	# Server config
	'api-url': '',
	'server-key': '',
}


##### AGENT-SERVER COMMUNICATION FUNCTIONS #####
JOB_STATE_ERROR       = -1
JOB_STATE_DOWNLOADING = 1
JOB_STATE_EXECUTING   = 2
JOB_STATE_FINISHED    = 3

def downloadFile(url, packageId, path, jobId):
	i = inventory.Inventory(config)
	data = {
		'jsonrpc': '2.0',
		'id': 1,
		'method': 'oco.agent.download',
		'params': {
			'uid': config['machine-uid'],
			'hostname': i.getHostname(),
			'timestamp': round(time.time(), 4),
			'package-id': packageId,
		}
	}
	data_json = json.dumps(data)
	headers = {
		'content-type': 'application/json',
		'x-oco-agent-signature': hmac.new(config['agent-key'].encode('utf-8'), data_json.encode('utf-8'), hashlib.sha256).hexdigest()
	}

	with requests.get(url, stream=True, data=data_json, headers=headers,
		timeout=(config['connection-timeout'],config['read-timeout'])) as r:
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

def jsonRequest(method, data, throw=True):
	global serverTimestamp

	i = inventory.Inventory(config)
	data = {
		'jsonrpc': '2.0',
		'id': 1,
		'method': method,
		'params': {
			'uid': config['machine-uid'],
			'hostname': i.getHostname(),
			'timestamp': round(time.time(), 4),
			'data': data
		}
	}
	data_json = json.dumps(data)
	headers = {
		'content-type': 'application/json',
		'x-oco-agent-signature': hmac.new(config['agent-key'].encode('utf-8'), data_json.encode('utf-8'), hashlib.sha256).hexdigest()
	}

	response = None
	try:
		# send request
		if(config['debug']): logger('< ' + data_json)
		response = requests.post(config['api-url'], data=data_json, headers=headers, timeout=(config['connection-timeout'],config['read-timeout']))

		# check response
		if(config['debug']): logger('> (' + str(response.elapsed.total_seconds()) + 's) [' + str(response.status_code) + '] ' + response.text)
		if(response.status_code != 200):
			raise Exception('Request failed with HTTP status code ' + str(response.status_code) + ': ' + response.text)

		# check timestamp greater than last
		response_json = response.json()
		if(not response_json or 'result' not in response_json or 'timestamp' not in response_json['result']):
			raise Exception('No timestamp in server response')
		if(float(response_json['result']['timestamp']) <= serverTimestamp):
			raise Exception('Server timestamp is the same or lower than last server timestamp - this might be an attack, aborting')
		serverTimestamp = float(response_json['result']['timestamp'])
		writeTimestamp(serverTimestamp)

		# check server signature if set in agent config
		if(config['server-key']):
			if('x-oco-server-signature' not in response.headers):
				raise Exception('Missing server signature')
			if(response.headers['x-oco-server-signature'] != hmac.new(config['server-key'].encode('utf-8'), response.text.encode('utf-8'), hashlib.sha256).hexdigest()):
				raise Exception('Invalid server signature '+response.headers['x-oco-server-signature']+' - check server_key')
		else:
			logger('Warning: no server-key set in agent config file - blindly trusting the server')

	except Exception as e:
		if(throw): raise Exception(e)
		else: logger(e)

	return response


##### VARIOUS AGENT FUNCTIONS #####

def isUserLoggedIn():
	if 'win32' in OS_TYPE:
		w = wmi.WMI()
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

def broadcastMessage(title, text):
	if 'linux' in OS_TYPE:
		if(which('notify-send')): # inform GUI users
			script = 'oco_agent/linux/notify-send-all.sh'
			if getattr(sys, 'frozen', False):
				script = os.path.join(sys._MEIPASS, 'oco_agent/linux/notify-send-all.sh')
			subprocess.check_output([script, title, text])
		if(which('wall')): # inform CLI users
			subprocess.check_output(['wall', text])

def removeAll(path):
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			os.remove(os.path.join(root, name))
		for name in dirs:
			os.rmdir(os.path.join(root, name))
	os.rmdir(path)

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

def encrypt(data, key):
	# pad key to 32 bytes (AES-256)
	key = (key[:32] + ("\x00"*(32-len(key)))).encode('utf-8')
	pad = lambda s : s+chr(16-len(s)%16)*(16-len(s)%16)
	iv = Random.get_random_bytes(16)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	encrypted_64 = base64.b64encode(cipher.encrypt(pad(data).encode())).decode('ascii')
	iv_64 = base64.b64encode(iv).decode('ascii')
	return {'iv':iv_64, 'data':encrypted_64}

def fileWriteFlags():
	if 'win32' in OS_TYPE:
		return os.O_WRONLY | os.O_CREAT
	else:
		return os.O_WRONLY | os.O_CREAT | os.O_SYNC

def writeTimestamp(tstamp):
	global DEFAULT_TSTAMP_PATH
	os.makedirs(os.path.dirname(DEFAULT_TSTAMP_PATH), exist_ok=True)
	with os.fdopen(os.open(DEFAULT_TSTAMP_PATH, fileWriteFlags()), 'w') as fileHandle:
		fileHandle.write(str(tstamp))

def writeConfig(section, key, value):
	global configParser, configFilePath
	if(not configParser.has_section(section)):
		configParser.add_section(section)
	configParser.set(section, key, value)
	with os.fdopen(os.open(configFilePath, fileWriteFlags()), 'w') as fileHandle:
		configParser.write(fileHandle)

def doInventoryUpdate(i, since):
	logger('Updating inventory data...')
	logins = []
	if(since):
		logins = i.getLogins(datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc))
	request2 = jsonRequest('oco.agent.update', {
		'hostname': i.getHostname(),
		'agent_version': __version__,
		'os': i.getOs(),
		'os_version': i.getOsVersion(),
		'os_license': i.getIsActivated(),
		'os_language': i.getLocale(),
		'kernel_version': i.getKernelVersion(),
		'architecture': i.getArchitecture(),
		'cpu': i.getCpu(),
		'ram': i.getRam(),
		'gpu': i.getGpu(),
		'serial': i.getMachineSerial(),
		'manufacturer': i.getMachineManufacturer(),
		'model': i.getMachineModel(),
		'bios_version': i.getBiosVersion(),
		'uptime': i.getUptime(),
		'boot_type': i.getUefiOrBios(),
		'secure_boot': i.getSecureBootEnabled(),
		'domain': i.getDomain(),
		'networks': i.getNics(),
		'screens': i.getScreens(),
		'printers': i.getPrinters(),
		'partitions': i.getPartitions(),
		'software': i.getInstalledSoftware(),
		'logins': logins,
		'users': i.getLocalUsers(),
		'battery_level': i.getBatteryLevel(),
		'battery_status': i.getBatteryStatus(),
		'devices': i.getUsbDevices(),
	})
	if(request2 != None and request2.status_code == 200):
		pd = PolicyDeployment()
		responseJson2 = request2.json()
		if('params' in responseJson2['result']
		and 'policies' in responseJson2['result']['params']):
			pd.applyPolicies(responseJson2['result']['params']['policies'])

# function for checking if agent is already running (e.g. due to long running software jobs)
def lockCheck():
	try:
		# if we can open the lockfile without error, no other instance is running
		with open(LOCKFILE_PATH, 'x') as lockfile:
			pid = str(os.getpid())
			lockfile.write(pid)
			logger('Starting with lock file (pid '+pid+')...')
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
					logger('Starting with lock file (pid '+pid+')...')
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
		except Exception as e:
			logger(type(e).__name__+':', e)
			traceback.print_exc()
		logger('Running in daemon mode. Waiting '+str(config['query-interval'])+' seconds to send next request.')
		exitEvent.wait(config['query-interval'])

# the main server communication function
# sends a "agent_hello" packet to the server and then executes various tasks, depending on the server's response
def mainloop(args):
	global restartFlag, configParser, forceUpdateFlag
	i = inventory.Inventory(config)

	# send initial request
	logger('Sending oco.agent.hello...', 'forceUpdateFlag:', forceUpdateFlag)
	request = jsonRequest('oco.agent.hello', {
		'agent_version': __version__,
		'networks': i.getNics(),
		'services': i.getServiceStatus(),
		'uptime': i.getUptime(),
		'battery_level': i.getBatteryLevel(),
		'battery_status': i.getBatteryStatus(),
		'force_update': forceUpdateFlag
	})
	forceUpdateFlag = False

	# check response
	if(request != None and request.status_code == 200):
		responseJson = request.json()

		# save server key if server key is not already set in local config
		if('server-key' in responseJson['result']['params']
		and (config['server-key'] == None or config['server-key'] == '')):
			logger('Write new config with updated server key...')
			writeConfig('server', 'server-key', responseJson['result']['params']['server-key'])
			config['server-key'] = configParser.get('server', 'server-key')

		# update agent key if requested
		if('agent-key' in responseJson['result']['params']
		and responseJson['result']['params']['agent-key'] != None):
			logger('Write new config with updated agent key...')
			writeConfig('agent', 'agent-key', responseJson['result']['params']['agent-key'])
			config['agent-key'] = configParser.get('agent', 'agent-key')

		# send computer info if requested
		if(responseJson['result']['params']['update'] == 1):
			since = '2000-01-01 00:00:00'
			if('logins-since' in responseJson['result']['params']):
				since = responseJson['result']['params']['logins-since']
			doInventoryUpdate(i, since)

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
					}, False)
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
						}, False)
						downloadFile(
							config['api-url'], job['package-id'], tempZipPath, job['id']
						)
						jsonRequest('oco.agent.update_job_state', {
							'job-id': job['id'], 'state': JOB_STATE_DOWNLOADING, 'return-code': None, 'download-progress': 101, 'message': ''
						}, False)
						with ZipFile(tempZipPath, 'r') as zipObj:
							logger('Unzipping into '+tempPath+'...')
							zipObj.extractall(tempPath)

					# change to tmp dir
					logger('Executing: '+job['procedure']+'...')
					jsonRequest('oco.agent.update_job_state', {
						'job-id': job['id'], 'state': JOB_STATE_EXECUTING, 'return-code': None, 'download-progress': 100, 'message': ''
					}, False)
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
					}, False)

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
							if(res.returncode == 0):
								restartFlag = True
								# Windows auomatically displays a warning when scheduling shutdown/restart
						else:
							res = subprocess.run('shutdown -r +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0):
								restartFlag = True
								broadcastMessage('System restart scheduled', 'Your computer is about to restart at '+str(datetime.datetime.now()+datetime.timedelta(seconds=timeout))+' because of a software update installed by your administrator.')

					# execute shutdown if requested
					if('shutdown' in job and job['shutdown'] != None and isinstance(job['shutdown'], int) and job['shutdown'] >= 0):
						timeout = 0
						if(isUserLoggedIn()): timeout = int(job['shutdown'])
						if 'win32' in OS_TYPE:
							res = subprocess.run('shutdown -s -t '+str(timeout*60), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0):
								restartFlag = True
								# Windows auomatically displays a warning when scheduling shutdown/restart
						else:
							res = subprocess.run('shutdown -h +'+str(timeout), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
							if(res.returncode == 0):
								restartFlag = True
								broadcastMessage('System shutdown scheduled', 'Your computer is about to shut down at '+str(datetime.datetime.now()+datetime.timedelta(seconds=timeout))+' initiated by your administrator.')

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
					}, False)
					os.chdir(tempfile.gettempdir())

		# send events from logs if requested
		if('events' in responseJson['result']['params']):
			i = inventory.Inventory(config)
			events = []
			for eventQuery in responseJson['result']['params']['events']:
				try:
					if(not 'log' in eventQuery or not 'query' in eventQuery or not 'since' in eventQuery): continue
					dateObjectSince = datetime.datetime.strptime(eventQuery['since'], '%Y-%m-%d %H:%M:%S')
					events += i.getEvents(eventQuery['log'], eventQuery['query'], dateObjectSince)
				except Exception as e:
					logger('Error reading events:', e)
			if(len(events) > 0):
				jsonRequest('oco.agent.events', {'events':events}, False)

		# update admin password if requested
		if('update-passwords' in responseJson['result']['params']):
			pwr = password_rotation.PasswordRotation()
			newPasswords = []
			newPasswordsRequest = []
			try:
				for item in responseJson['result']['params']['update-passwords']:
					newPassword = pwr.generatePassword(item['alphabet'], item['length'])
					newPasswords.append({
						'username': item['username'],
						'password': newPassword,
						'old_password': item['old_password'] if 'old_password' in item else ''
					})
					newPasswordsRequest.append({
						'username': item['username'],
						'password': encrypt(newPassword, config['agent-key'])
					})
				# store the new passwords on the server
				jsonRequest('oco.agent.passwords', {'passwords':newPasswordsRequest})
				# change them locally - only if jsonRequest succeeded to be sure that new passwords do not get lost
				for item in newPasswords:
					try:
						pwr.updatePassword(item['username'], item['password'], item['old_password'])
					except Exception as e2:
						# in case of failure, e.g. user does not exist, we need revoke the password on the server
						logger('Unable to rotate password for "'+str(item['username'])+'":', e2, '(trying to revoke)')
						try:
							jsonRequest('oco.agent.passwords', {
								'passwords': [
									{'username':item['username'], 'password':encrypt(item['password'], config['agent-key']), 'revoke':True}
								]
							})
						except Exception as e3:
							logger('Unable to revoke password for "'+str(item['username'])+'":', e3)
			except Exception as e:
				logger('Password rotation error:', e)


def signal_handler(signum, frame):
	global exitEvent
	exitEvent.set()

def logon_handler(action, pContext, event):
	global forceUpdateFlag
	logger('Got logon event:', event)
	forceUpdateFlag = True

##### MAIN ENTRY POINT - AGENT INITIALIZATION #####
def main():
	global configFilePath, configParser, config, serverTimestamp, forceUpdateFlag

	try:
		# read arguments
		parser = argparse.ArgumentParser()
		parser.add_argument('--config', default=DEFAULT_CONFIG_PATH, type=str, help='Path to config file')
		parser.add_argument('--daemon', action='store_true', help='Run in daemon mode (loop until SIGTERM/SIGINT)')
		parser.add_argument('--force', action='store_true', help='Force inventory & policy update')
		args = parser.parse_args()

		# set conf path
		configFilePath = args.config
		logger('Starting with config file: '+configFilePath+' ...')

		# set force flag
		if(args.force):
			forceUpdateFlag = True

		# read timestamp
		if(os.path.isfile(DEFAULT_TSTAMP_PATH)):
			try:
				with open(DEFAULT_TSTAMP_PATH, 'r') as f:
					serverTimestamp = float(f.read())
			except Exception as e:
				logger('Unable to load prev timestamp:', e)

		# read config
		i = inventory.Inventory(config)
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
			config['machine-uid'] = configParser['agent'].get('machine-uid', i.getMachineUid())
		if(configParser.has_section('server')):
			config['api-url'] = configParser['server'].get('api-url', config['api-url'])
			config['server-key'] = configParser['server'].get('server-key', config['server-key'])
		if(configParser.has_section('windows')):
			config['windows']['username-with-domain'] = (int(configParser['windows'].get('username-with-domain', config['windows']['username-with-domain'])) == 1)
		if(configParser.has_section('linux')):
			config['linux']['local-users-min-uid'] = int(configParser['windows'].get('local-users-min-uid', config['linux']['local-users-min-uid']))

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

		# on Windows, start the logon listener
		if 'win32' in OS_TYPE:
			from winevt_ng import EventLog
			try:
				logger('Starting logon listener...')
				# instant policy update after new user logon
				subscription = EventLog.Subscribe(
					"Security",
					"*[(EventData[Data[@Name='LogonType']='2'] or EventData[Data[@Name='LogonType']='10'] or EventData[Data[@Name='LogonType']='11']) and System[(EventID='4624')]]",
					logon_handler
				)
			except Exception as e2:
				logger('Unable to start logon listener:', e2)

	except Exception as e:
		logger('main():', type(e).__name__+':', e)
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
		except Exception as e:
			logger(type(e).__name__+':', e)
			traceback.print_exc()
			sys.exit(1)

if __name__ == '__main__':
	main()
