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
from zipfile import ZipFile
from dns import resolver, rdatatype


##### CONSTANTS #####

from . import __version__, logger, guessEncodingAndDecode
EXECUTABLE_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
DEFAULT_CONFIG_PATH = EXECUTABLE_PATH+'/oco-agent.ini'
LOCKFILE_PATH = tempfile.gettempdir()+'/oco-agent.lock'
OS_TYPE = sys.platform.lower()


##### OS SPECIFIC IMPORTS #####

if 'win32' in OS_TYPE:
	import wmi, ctypes
	from .windows import inventory, password_rotation

elif 'linux' in OS_TYPE:
	from .linux import inventory, password_rotation

elif 'darwin' in OS_TYPE:
	from .macos import inventory, password_rotation
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

def jsonRequest(method, data, throw=False):
	i = inventory.Inventory(config)
	headers = {'content-type': 'application/json'}
	data = {
		'jsonrpc': '2.0',
		'id': 1,
		'method': method,
		'params': {
			'uid': config['machine-uid'],
			'hostname': i.getHostname(),
			'agent-key': config['agent-key'],
			'data': data
		}
	}
	data_json = json.dumps(data)

	response = None
	try:
		# send request
		if(config['debug']): logger('< ' + data_json)
		response = requests.post(config['api-url'], data=data_json, headers=headers, timeout=(config['connection-timeout'],config['read-timeout']))

		# check response
		if(config['debug']): logger('> (' + str(response.elapsed.total_seconds()) + 's) [' + str(response.status_code) + '] ' + response.text)
		if(response.status_code != 200):
			raise Exception('Request failed with HTTP status code ' + str(response.status_code))

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
	i = inventory.Inventory(config)

	# send initial request
	logger('Sending agent_hello...')
	request = jsonRequest('oco.agent.hello', {
		'agent_version': __version__,
		'networks': i.getNics(),
		'services': i.getServiceStatus(),
		'uptime': i.getUptime()
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
		if(responseJson['result']['params']['update'] == 1):
			logger('Updating inventory data...')

			since = '2000-01-01 00:00:00'
			if('logins-since' in responseJson['result']['params']):
				since = responseJson['result']['params']['logins-since']
			logins = i.getLogins(datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc))
			jsonRequest('oco.agent.update', {
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
							{'uid': config['machine-uid'], 'hostname': i.getHostname(), 'agent-key': config['agent-key'], 'id': job['package-id']},
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
				jsonRequest('oco.agent.events', {'events':events})

		# update admin password if requested
		if('update-passwords' in responseJson['result']['params']):
			pwr = password_rotation.PasswordRotation()
			newPasswords = []
			try:
				for item in responseJson['result']['params']['update-passwords']:
					newPassword = pwr.generatePassword(item['alphabet'], item['length'])
					newPasswords.append({'username':item['username'], 'password':newPassword})
				# store the new passwords on the server
				jsonRequest('oco.agent.passwords', {'passwords':newPasswords}, True)
				# change them locally - only if jsonRequest succeeded to be sure that new passwords do not get lost
				for item in newPasswords:
					try:
						pwr.updatePassword(item['username'], item['password'])
					except Exception as e2:
						# in case of failure, e.g. user does not exist, we need revoke the password on the server
						logger('Unable to rotate password for '+str(item['username'])+':', e2, '(trying to revoke)')
						try:
							jsonRequest('oco.agent.passwords', {'passwords':[{'username':item['username'], 'password':item['password'], 'revoke':True}]}, True)
						except Exception as e3:
							logger('Unable to revoke password for '+str(item['username'])+':', e3)
			except Exception as e:
				logger('Password rotation error:', e)


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
