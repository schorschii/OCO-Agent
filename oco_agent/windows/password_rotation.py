#!/usr/bin/python3

import subprocess

from .. import base_password_rotation, logger


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword):
		# update password in local database
		cmd = ['net', 'user', username, newPassword]
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
		if res.returncode == 0:
			logger('Changed password of user "'+username+'" locally')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))
