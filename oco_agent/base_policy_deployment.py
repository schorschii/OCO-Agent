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

	def applyJsonPolicy(self, scope, path, key, value):
		# load existing file if exists
		jsonStruct = {}
		if(os.path.isfile(path)):
			with open(path, 'r') as file:
				jsonStruct = json.load(file)

		# append value as dict/array if string can be parsed as JSON
		if(isinstance(value, str)):
			try:
				parsed = json.loads(value)
				value = parsed
			except json.decoder.JSONDecodeError: pass

		# apply new values atomic - keep existing (sub)keys/values
		keyPath = key.split('\\')
		value = self.insertValueInStruct(jsonStruct, keyPath, value)

		# write updated policies file
		os.makedirs(os.path.dirname(path), exist_ok=True)
		with open(path, 'w') as file:
			json.dump(jsonStruct, file, indent=2)

	def insertValueInStruct(self, struct, keyPath, value):
		if(len(keyPath) == 1):
			struct[keyPath[0]] = value
		else:
			subStruct = {}
			if(keyPath[0] in struct): subStruct = struct[keyPath[0]]
			struct[keyPath[0]] = self.insertValueInStruct(subStruct, keyPath[1:], value)
		return struct
