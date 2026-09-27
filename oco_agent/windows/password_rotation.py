#!/usr/bin/python3

import subprocess

from .. import base_password_rotation, logger

# maximum time (seconds) to wait for the command before giving up rather than
# risking the agent hanging indefinitely mid-rotation
NET_USER_TIMEOUT = 30


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword, oldPassword=None):
		# update password in local database
		cmd = ['net', 'user', username, newPassword]
		try:
			res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=NET_USER_TIMEOUT)
		except subprocess.TimeoutExpired:
			raise Exception(' '.join(cmd)+' did not respond within '+str(NET_USER_TIMEOUT)+'s, aborting')
		if res.returncode == 0:
			logger('Changed password of user "'+username+'" locally')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))
