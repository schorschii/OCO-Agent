#!/usr/bin/python3

from .. import logger

from winevt_ng import EventLog
import winreg
import datetime

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

def getLogins(since, usernameWithDomain=False):
	# server's `since` value is in UTC
	dateObjectSince = datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)

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
				'guid': queryRegistryUserGuid(event['TargetUserSid']),
				'display_name': queryRegistryUserDisplayName(event['TargetUserSid']),
				'username': event['TargetDomainName']+'\\'+event['TargetUserName'] if usernameWithDomain else event['TargetUserName'],
				'console': event['IpAddress'],
				'timestamp': dateObject.strftime('%Y-%m-%d %H:%M:%S')
			})
	except Exception as e:
		logger('Error getting logins:', e)
	return users

def queryRegistryUserDisplayName(querySid):
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

def queryRegistryUserGuid(querySid):
	# get user GUID from ProfileList in registry
	try:
		key = f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{querySid}'
		reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
		guid, regtype = winreg.QueryValueEx(reg, 'Guid')
		return guid.strip('{}')
	except WindowsError as e: pass
	return None
