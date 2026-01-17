#!/usr/bin/python3

import os, sys
import json

from . import logger


class BasePolicyDeployment:

	manifestationModuleMap = {}

	def __init__(self):
		self.manifestationModuleMap['JSON'] = self.applyJsonPolicy

	def applyPolicies(self, policyDict):
		for scope, policies in policyDict.items():
			for definition, value in policies.items():
				try:
					logger(f'Processing {scope} policy {definition} => {value}')
					self.applyPolicy(scope, definition, value)
				except Exception as e:
					logger('Failed to apply policy:', e)

	def applyPolicy(self, scope, definition, value):
		splitter = definition.split(':')
		if(len(splitter) != 3):
			raise Exception('policy key does not consist of 3 parts separated by :')
		module = splitter[0]
		path = splitter[1]
		key = splitter[2]

		if(module not in self.manifestationModuleMap):
			raise Exception(f'manifestation module {module} not supported')

		self.manifestationModuleMap[module](scope, path, key, value)

	def applyJsonPolicy(self, scope, file, key, value):
		print('!!! somebody needs to implement this', file, key, value)
