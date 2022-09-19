# Apt Software Query
Architecture Decision Record  
Lang: en  
Encoding: utf-8  
Created: 2022-09-19  
Updated: -  
Author: Georg Sieber

## Decision
The agent queries installed software under Linux via `apt list --installed`.

## Status
Accepted

## Context
Multiple architectures of the same .deb package can be installed on a single system. Those packages have the same name and version, that's why the package only appears once in the OCO server's database. Installed architectures of a package are currently not monitored. This means that the apt output may contain more entries that you can see on the OCO server.

## Consequences
Currently, only apt-based distributions are supported.
