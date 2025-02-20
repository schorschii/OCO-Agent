#!/usr/bin/python3

# local_users is a separate file since it is used by macOS too
import pwd, grp

from .. import logger


def getLocalUsers(minUid, maxUid):
	users = []
	for p in pwd.getpwall():
		if(p.pw_uid < minUid): continue
		if(p.pw_uid > maxUid): continue
		users.append({
			'username': p.pw_name, 'display_name': p.pw_gecos.split(',')[0],
			'uid': p.pw_uid, 'gid': p.pw_gid,
			'home': p.pw_dir, 'shell': p.pw_shell,
			'disabled': p.pw_passwd=='*'
		})
	return users
