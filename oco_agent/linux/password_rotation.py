#!/usr/bin/python3

import subprocess
from shutil import which
from crypt import crypt

from .. import base_password_rotation, logger

# maximum time (seconds) to wait for usermod before giving up rather than
# risking the agent hanging indefinitely mid-rotation
USERMOD_TIMEOUT = 30


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword, oldPassword=None):
		# check if usermod is in PATH
		if(which('usermod') is None):
			raise Exception('usermod is not in PATH')

		# generate new values
		newPasswordHashed = crypt(newPassword)

		# update password in local database
		cmd = ['usermod', '-p', newPasswordHashed, username]
		try:
			res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=USERMOD_TIMEOUT)
		except subprocess.TimeoutExpired:
			raise Exception(' '.join(cmd)+' did not respond within '+str(USERMOD_TIMEOUT)+'s, aborting')
		if res.returncode == 0:
			logger('Changed password of user "'+username+'" locally')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))
