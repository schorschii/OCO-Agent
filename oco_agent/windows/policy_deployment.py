#!/usr/bin/python3

import os, sys
import winreg
import subprocess

from .. import base_policy_deployment, logger


class PolicyDeployment(base_policy_deployment.BasePolicyDeployment):

	def __init__(self):
		super().__init__()
		# register platform-specific manifestation module
		self.manifestationModuleMap['REGISTRY'] = self.applyRegistryPolicy
		self.mountedUserStructs = []

	# override applyPolicies from superclass to execute cleanup function at the end
	def applyPolicies(self, policyDict):
		super().applyPolicies(policyDict)
		self.__cleanup()

	def __cleanup(self):
		# cleanup our registry mounts
		for sid in reversed(self.mountedUserStructs):
			cmd = subprocess.run(f'reg unload HKEY_USERS\\{sid}')
			if(cmd.returncode):
				logger('ERROR: unable to unload user registry', sid)
			else:
				logger('Unloaded user registry', sid)
				self.mountedUserStructs[:] = [x for x in self.mountedUserStructs if x != sid]

	def __getSidByGuid(self, queryGuid):
		# get user SID from ProfileGuid in registry
		queryGuid = '{'+queryGuid+'}'
		try:
			key = f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileGuid\\{queryGuid}'
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
			sid, regtype = winreg.QueryValueEx(reg, 'SidString')
			return sid
		except WindowsError as e: pass
		return None

	def __getProfilePathBySid(self, querySid):
		# get user SID from ProfileGuid in registry
		queryGuid = '{'+querySid+'}'
		try:
			key = f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{querySid}'
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
			sid, regtype = winreg.QueryValueEx(reg, 'ProfileImagePath')
			return sid
		except WindowsError as e: pass
		return None

	def applyRegistryPolicy(self, scope, path, key, value):
		if(scope == 'machine'):
			winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_CREATE_SUB_KEY)
			reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_WRITE)
			winreg.SetValueEx(reg, key, 0, winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ, value)

		else:
			sid = self.__getSidByGuid(scope)
			if(not sid): raise Exception(f'Scope {scope} not found')

			# check if already mounted (= user logged in) or we need to mount it
			try:
				winreg.OpenKey(winreg.HKEY_USERS, sid, 0, winreg.KEY_READ)
			except WindowsError:
				profilePath = self.__getProfilePathBySid(sid)
				cmd = subprocess.run(f'reg load HKEY_USERS\\{sid} {profilePath}\\NTUSER.DAT')
				if(cmd.returncode): raise Exception(f'Unable to load user registry {sid}')
				self.mountedUserStructs.append(sid)

			winreg.CreateKeyEx(winreg.HKEY_USERS, sid+'\\'+path, 0, winreg.KEY_CREATE_SUB_KEY)
			reg = winreg.OpenKey(winreg.HKEY_USERS, sid+'\\'+path, 0, winreg.KEY_WRITE)
			winreg.SetValueEx(reg, key, 0, winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ, value)
