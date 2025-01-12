#!/usr/bin/python3

import secrets


class BasePasswordRotation:
	def generatePassword(self, alphabet, length):
		return ''.join(secrets.choice(alphabet) for i in range(length))
