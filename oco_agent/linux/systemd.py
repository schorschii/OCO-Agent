#!/usr/bin/python3

from .. import logger

import time, re, json


def getEvents(query, dateObjectSince, maxBatch, debug=False):
	foundEvents = []
	startTime = time.time()
	logger('Querying events from journalctl...')
	queryData = json.loads(query)

	# this module is only available on systemd distros and not via PyPI
	# it's OK if the import throws an error
	from systemd import journal

	j = journal.Reader()
	if('unit' in queryData):
		for x in queryData['unit'].split(','): j.add_match(_SYSTEMD_UNIT=x.strip())
	if('identifier' in queryData):
		for x in queryData['identifier'].split(','): j.add_match(SYSLOG_IDENTIFIER=x.strip())
	if('priority' in queryData):
		for x in queryData['priority'].split(','): j.add_match(PRIORITY=x.strip())
		#j.log_level(journal.LOG_INFO)

	j.seek_realtime(dateObjectSince)
	j.get_next()
	for entry in j:
		if entry['MESSAGE'] != '' and (not 'grep' in queryData or re.search(queryData['grep'], entry['MESSAGE'])):
			foundEvents.append({
				'log': entry['_SYSTEMD_UNIT'] if '_SYSTEMD_UNIT' in entry else 'journalctl',
				'provider': entry['SYSLOG_IDENTIFIER'] if 'SYSLOG_IDENTIFIER' in entry else '',
				'event_id': str(entry['SYSLOG_FACILITY']) if 'SYSLOG_FACILITY' in entry else '',
				'level': str(entry['PRIORITY']) if 'PRIORITY' in entry else '',
				'timestamp': entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'),
				'data': {'message':entry['MESSAGE']}
			})
			if(len(foundEvents) > maxBatch): break

	if(debug): print('  took '+str(time.time()-startTime))
	return foundEvents
