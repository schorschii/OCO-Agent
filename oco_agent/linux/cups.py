#!/usr/bin/python3

# CUPS parsing is a separate file since it is used by macOS too
import os

from .. import logger


CUPS_CONFIG = '/etc/cups/printers.conf'

def getPrinters():
	printers = []
	if(not os.path.exists(CUPS_CONFIG)):
		return printers

	try:
		with open(CUPS_CONFIG, 'r', encoding='utf-8', errors='replace') as file:
			printer = {'name': '', 'driver': '', 'paper': '', 'dpi': '', 'uri': '', 'status': ''}
			for line in file:
				l = line.rstrip('\n')
				if(l.startswith('<DefaultPrinter ') or l.startswith('<Printer ')):
					printer = {
						'name': l.split(' ', 1)[1].rstrip('>'),
						'driver': '', 'paper': '', 'dpi': '', 'uri': '', 'status': ''
					}
				if(l.startswith('MakeModel ')):
					printer['driver'] = l.split(' ', 1)[1]
				if(l.startswith('DeviceURI ')):
					printer['uri'] = l.split(' ', 1)[1]
				if(l.startswith('</DefaultPrinter>') or l.startswith('</Printer>')):
					if(printer['name'] != ''):
						printers.append(printer)
	except Exception as e:
		logger('Unable to get CUPS printers:', e)
	return printers
