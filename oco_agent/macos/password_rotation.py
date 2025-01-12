#!/usr/bin/python3

import subprocess

from .. import base_password_rotation, logger


class PasswordRotation(base_password_rotation.BasePasswordRotation):

	def updatePassword(self, username, newPassword):
		raise Exception('not implemented')
