#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2015 Gianni Amato
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ----------------------------------------------------------------------

# BETA

import re
import string
import magic
import json
import binascii

def get_process(stream):
    result = ''
    while True:
		data = stream.read(1024*4)
		if not data: break
		for char in data:
			if char in string.printable:
				result += char
				continue
			if len(result) >= 4:
				yield result
			result = ''

def filetype(filename):
	type = magic.from_file(filename)
	return type

def get_unicode(filename):
	PEtoUnicode = open(filename, 'rb').read()
	pattern = re.compile(ur'(?:[\x20-\x7E][\x00]){3,}')
	return [w.decode('utf-16le') for w in pattern.findall(PEtoUnicode)]

def get_ascii(filename):
	PEtoStr = open(filename, 'rb')
	return [w.decode('utf-8') for w in get_process(PEtoStr)]

# MAIN
def get(filename):
	strings = []
	ascii = []
	utf16le = []
	
	# Filetype
	ftype = filetype(filename)
	
	# UTF-16
	if re.findall(r'UTF-16', ftype) and re.findall(r'text', ftype):
		utf16le = get_unicode(filename)
		utf16le = str(utf16le).split(' ')
		strings = utf16le
	# ASCII/UTF-8
	elif re.findall(r'ASCII|UTF-8', ftype) and re.findall(r'text', ftype):
		textfile = open(filename, 'r')
		ascii = textfile.read().split()
		textfile.close()
		strings = ascii
	# BINARY (ASCII/UTF-8 + UTF-16)
	else:
		# re.findall(r'MIME entity|XML', ftype):
		ascii = list(set(get_ascii(filename)))
		utf16le = list(set(get_unicode(filename)))
		strings = utf16le + ascii + strings

		if not strings:
			try:
				strings = open(filename, 'r').read().decode('utf-8').split('\n')
			except:
				strings = open(filename, 'r').read().decode('latin-1').split('\n')

			strings = [repr(string) for string in strings]
	
	return json.dumps({'filetype': ftype,
						'content': strings},
						sort_keys=False, 
						indent=4, separators=(',', ': '))


