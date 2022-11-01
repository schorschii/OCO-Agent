# DNS Auto Discovery
Architecture Decision Record  
Lang: en  
Encoding: utf-8  
Created: 2022-10-29  
Updated: -  
Author: Georg Sieber

## Decision
The OCO agent discovers its server automatically via the DNS SRV record `_oco._tcp.example.com` and writes the server name into the config file for further use if the `api-url` entry in the config file is currently empty.

## Status
Accepted

## Context
The DNS auto discovery is only done once (on the first startup, if the `api-url` option in the config file is empty) because of security concerns. The first startup is assumed to be in a trusted environment (TOFU, Trust On First Use principle).

If the client is addressed via DHCP it could be a security issue querying the DNS SRV record every time the agent starts as an attacker could set up his own DHCP server with a custom search domain. Then, the agent would query the SRV record `_oco._tcp.` from the attackers domain. This would cause the agent to connect to the attacker's server. Since OCO focuses on all client computer devices such as mobile notebooks, this is a realistic scenario.

## Consequences
Changing the server name can not easily be done by changing the SRV record. The agent will still use the old server name in its config file.
