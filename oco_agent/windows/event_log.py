#!/usr/bin/python3

from .. import logger
from .registry import queryRegistryUserDisplayName, queryRegistryUserGuid

from winevt_ng import EventLog
import time, datetime


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

def getLogins(dateObjectSince, usernameWithDomain=False):
	users = []
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
	return users

def getEvents(log, query, dateObjectSince, maxBatch, debug=False):
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

	if(debug): print('  took '+str(time.time()-startTime))
	return foundEvents
