#!/usr/bin/python3

import os, sys
import json
import subprocess

from .. import base_policy_deployment, logger


class PolicyDeployment(base_policy_deployment.BasePolicyDeployment):

	def __init__(self):
		super().__init__()
		# register platform-specific manifestation module
		self.manifestationModuleMap['DEFAULTS'] = self.applyDefaultsPolicy

	def applyDefaultsPolicy(self, scope, path, key, value, apply):
		if(scope == 'machine'):
			if(apply):
				if(isinstance(value, list)):
					cmd = subprocess.run(['defaults', 'write', path, key, '-array'] + value)
				elif(isinstance(value, dict)):
					value = json.dumps(value, separators=(', ',' = ')).replace('"', '')
					cmd = subprocess.run(['defaults', 'write', path, key, '-dict', str(value)])
				elif(isinstance(value, int)):
					cmd = subprocess.run(['defaults', 'write', path, key, '-int', str(value)])
				else:
					cmd = subprocess.run(['defaults', 'write', path, key, '-string', str(value)])
			else:
				cmd = subprocess.run(['defaults', 'delete', path, key])
			if(cmd.returncode): raise Exception(f'"defaults" command returned '+str(cmd.returncode))

		else:
			raise Exception('User policies not implemented yet for macOS')
