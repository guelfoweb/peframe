#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string

def convert_char(char):
	if char in string.ascii_letters or \
		char in string.digits or \
		char in string.punctuation or \
		char in string.whitespace:
		return char
	else:
		return r'\x%02x' % ord(char)

def convert_to_printable(s):
	return ''.join([convert_char(c) for c in s])
			
def get(pe):
	ret = {}	
	if hasattr(pe, 'VS_VERSIONINFO'):
		if hasattr(pe, 'FileInfo'):
			for finfo in pe.FileInfo:
				for entry in finfo:
					if hasattr(entry, 'StringTable'):
						for st_entry in entry.StringTable:
							for key, entry in list(st_entry.entries.items()):
								ret.update({key.decode(): entry.decode()})
	
	return ret
