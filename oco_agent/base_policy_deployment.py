#!/usr/bin/python3

import os, sys
import json

from . import logger


class BasePolicyDeployment:

	EXECUTABLE_PATH   = os.path.abspath(os.path.dirname(sys.argv[0]))
	POLICY_CACHE_PATH = EXECUTABLE_PATH+'/policies.json'

	manifestationModuleMap = {}

	previousPolicies = {}

	def __init__(self):
		# register default manifestation modules
		self.manifestationModuleMap['JSON'] = self.applyJsonPolicy

		# load last policies
		OS_TYPE = sys.platform.lower()
		if 'linux' in OS_TYPE or 'darwin' in OS_TYPE:
			self.POLICY_CACHE_PATH = '/var/lib/oco-agent/policies.json'

		if(os.path.isfile(self.POLICY_CACHE_PATH)):
			try:
				with open(self.POLICY_CACHE_PATH, 'r') as f:
					self.previousPolicies = json.load(f)
			except Exception as e:
				logger('Unable to load prev policies:', e)

	def applyPolicies(self, policyDict):
		# apply new policies from server
		if(not isinstance(policyDict, dict)): return
		currentPolicies = {}
		for scope, policies in policyDict.items():
			if(not isinstance(policies, dict)): continue
			if(not scope in currentPolicies):
				currentPolicies[scope] = {}
			for definition, value in policies.items():
				try:
					logger(f'Processing {scope} policy {definition} => {value}')
					self.applyPolicy(scope, definition, value, True)
					currentPolicies[scope][definition] = value
				except Exception as e:
					logger('Failed to apply policy:', e)

		# remove obsolete policies which are set previously
		if(isinstance(self.previousPolicies, dict)):
			for prevScope, prevPolicies in self.previousPolicies.items():
				if(not isinstance(prevPolicies, dict)): continue
				for prevDefinition, prevValue in prevPolicies.items():
					if(prevScope not in currentPolicies
					or prevDefinition not in currentPolicies[prevScope]):
						try:
							logger(f'Deleting obsolete {prevScope} policy {prevDefinition}')
							self.applyPolicy(prevScope, prevDefinition, prevValue, False)
						except Exception as e:
							logger('Failed to delete policy:', e)

		# store our last applied policies
		self.previousPolicies = currentPolicies
		os.makedirs(os.path.dirname(self.POLICY_CACHE_PATH), exist_ok=True)
		with open(self.POLICY_CACHE_PATH, 'w') as f:
			json.dump(self.previousPolicies, f, indent=2)

	def applyPolicy(self, scope, definition, value, apply):
		splitter = definition.split(':')
		if(len(splitter) < 2):
			raise Exception('policy key does not consist of at least 2 parts separated by :')
		module = splitter[0]
		path = splitter[1]
		key = splitter[2] if len(splitter) > 2 else None

		if(module not in self.manifestationModuleMap):
			raise Exception(f'manifestation module {module} not supported')

		self.manifestationModuleMap[module](scope, path, key, value, apply)

	def applyJsonPolicy(self, scope, path, key, value, apply):
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
		value = self.insertValueInStruct(jsonStruct, keyPath, value, apply)

		# write updated policies file
		os.makedirs(os.path.dirname(path), exist_ok=True)
		with open(path, 'w') as file:
			json.dump(jsonStruct, file, indent=2)

	def insertValueInStruct(self, struct, keyPath, value, apply):
		if(len(keyPath) == 1):
			if(apply):
				struct[keyPath[0]] = value
			elif(keyPath[0] in struct):
				del struct[keyPath[0]]
		else:
			subStruct = {}
			if(keyPath[0] in struct): subStruct = struct[keyPath[0]]
			struct[keyPath[0]] = self.insertValueInStruct(subStruct, keyPath[1:], value, apply)
		return struct
