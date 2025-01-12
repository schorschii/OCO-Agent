__title__   = 'OCO-Agent'
__author__  = 'Georg Sieber'
__license__ = 'GPL-3.0'
__version__ = '1.1.5'
__website__ = 'https://github.com/schorschii/OCO-Agent'

__all__ = [__author__, __license__, __version__]


import datetime

def logger(*text):
	print('['+str(datetime.datetime.now())+']', *text)

def guessEncodingAndDecode(textBytes, codecs=['utf-8', 'cp1252', 'cp850']):
	for codec in codecs:
		try:
			return textBytes.decode(codec)
		except UnicodeDecodeError: pass
	return textBytes.decode(sys.stdout.encoding, 'replace') # fallback: replace invalid characters
