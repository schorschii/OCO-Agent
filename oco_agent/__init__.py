__title__   = 'OCO-Agent'
__author__  = 'Georg Sieber'
__license__ = 'GPL-3.0'
__version__ = '1.1.4'
__website__ = 'https://github.com/schorschii/OCO-Agent'

__all__ = [__author__, __license__, __version__]


import datetime

def logger(*text):
	print('['+str(datetime.datetime.now())+']', *text)
