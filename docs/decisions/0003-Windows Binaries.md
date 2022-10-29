# Windows Binaries
Architecture Decision Record  
Lang: en  
Encoding: utf-8  
Created: 2022-10-29  
Updated: -  
Author: Georg Sieber

## Decision
The OCO agent for Windows is compiled via PyInstaller without the "-F" (--onefile) flag. This produces a program directory with all libraries besides the main executable file.

## Status
Accepted

## Context
With Windows 10, Microsoft introduced a feature called "Storage Sense" which automatically cleans up temporary diectories like `C:\Windows\TEMP`. This feature collides with the "--onefile" mechanism from PyInstaller because when starting a binary produced by "pyinstaller --onefile", it will first unpack the Python Base Library into `C:\Windows\TEMP`. When the python program now runs for a longer time, it is possible that Storage Sense cleans up this directory and removes the Base Library, which makes the compiled python script end up in errors like `[Errno 2] No such file or directory: 'C:\\Windows\\TEMP\\_MEI128402\\base_library.zip'`.

## Consequences
A custom PyInstaller .spec file is necessary to union the compiled oco-agent.py an service-wrapper into one target directory as described in [1].

As a positive side effect, this mechnanism of combining both scripts reduces the size of the shipped OCO agent as both scripts now share common libraries.


[1] https://pyinstaller.org/en/latest/spec-files.html#multipackage-bundles
