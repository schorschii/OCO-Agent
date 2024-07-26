#!/usr/bin/python3

from .. import logger

import winreg


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
