#!/usr/bin/python3

import subprocess
from shutil import which

from .. import base_password_rotation, logger

# maximum time (seconds) to wait for a dscl call before giving up rather than
# risking the agent hanging indefinitely mid-rotation
DSCL_TIMEOUT = 30


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword, oldPassword):
		# check if dscl is in PATH
		if(which('dscl') is None):
			raise Exception('dscl is not in PATH')

		# update password in local database
		cmd = ['dscl', '.', '-passwd', '/Users/'+username, oldPassword, newPassword]
		try:
			res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=DSCL_TIMEOUT)
		except subprocess.TimeoutExpired:
			raise Exception(' '.join(cmd)+' did not respond within '+str(DSCL_TIMEOUT)+'s, aborting')
		if res.returncode != 0:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))
		logger('Changed password of user "'+username+'" locally')

		# verify the new password is really active before the caller reports it
		# anywhere - catches a "success" that doesn't actually reflect reality
		self._verifyPassword(username, newPassword)

	def _verifyPassword(self, username, password):
		cmd = ['dscl', '.', '-authonly', username, password]
		try:
			res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True, timeout=DSCL_TIMEOUT)
		except subprocess.TimeoutExpired:
			raise Exception(' '.join(cmd)+' did not respond within '+str(DSCL_TIMEOUT)+'s, aborting')
		if res.returncode != 0:
			raise Exception('Post-change verification failed for user "'+username+'" (dscl -authonly exit code '+str(res.returncode)+')')
		logger('Verified new password of user "'+username+'" locally')
