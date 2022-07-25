# User Login Query (Domain, GUID)
Architecture Decision Record  
Lang: en  
Encoding: utf-8  
Date: 2022-07-25  
Author: Georg Sieber

## Decision
The agent queries user logins from the system event log (Windows), `/var/log/utmp` (Linux) or the `last` command (macOS).

## Status
Accepted

## Context
Those 3 information sources do not provide all desired information. The logon domain can only be retrieved on Windows but even here only the NetBIOS domain name is available (but the FQDN would be desired). Also, there is no info about the user GUID (`objectGUID`) in order to track username changes.

`utmp` and `last` on Linux and macOS do not provide logon domain information at all.

## Consequences
It is not possible to get user domain information on Linux and macOS. Therefore, the feature to prepend the domain name to the username can be *optionally* activated in the agent on Windows clients (using the configuration option `username-with-domain = 0` in the `[windows]` section). It is disabled by default because this feature may not be desired if you want to track user logins over multiple operating systems. This is not possible if the domain is prepended only on windows clients.

Furthermore, it is not possible to track username changes because of the missing `objectGUID` info.
