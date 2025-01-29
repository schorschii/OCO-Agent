#!/usr/bin/python3

import subprocess
from shutil import which

from .. import base_password_rotation, logger


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword, oldPassword):
		# check if usermod is in PATH
		if(which('dscl') is None):
			raise Exception('dscl is not in PATH')

		# update password in local database
		cmd = ['dscl', '.', '-passwd', '/Users/'+username, oldPassword, newPassword]
		res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
		if res.returncode == 0:
			logger('Changed password of user "'+username+'" locally')
		else:
			raise Exception(' '.join(cmd)+' returned non-zero exit code '+str(res.returncode))
