# User Login Query (Domain, GUID)
Architecture Decision Record  
Lang: en  
Encoding: utf-8  
Created: 2022-07-25  
Updated: 2022-09-17  
Author: Georg Sieber

## Decision
The agent queries user logins from the system event log (Windows), `/var/log/utmp` (Linux) or the `last` command (macOS).

## Status
Accepted

## Context
The 3 information sources from the different operating systems do not provide all desired information.

Windows Event Log:
- provides the NetBIOS domain name (but the FQDN would be desired)
- user GUID must be queried from registry

Linux and macOS:
- no standardized/official/easy way to get domain or user GUID information
  - on Linux, the SSSD database files can may be queried to get those information - contributions welcome

## Consequences
It is not possible to get user domain information on Linux and macOS. Therefore, the feature to prepend the domain name to the username can be *optionally* activated in the agent on Windows clients (using the configuration option `username-with-domain = 0` in the `[windows]` section). It is disabled by default because this feature may not be desired if you want to track user logins over multiple operating systems. This is not possible if the domain is prepended only on windows clients.
