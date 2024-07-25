#!/usr/bin/python3

from .. import logger

import utmp
import datetime, os, shlex

def getLogins(since):
	# server's `since` value is in UTC
	dateObjectSince = datetime.datetime.strptime(since, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)

	users = []
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
	return users
