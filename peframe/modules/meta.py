#!/usr/bin/env python

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
	        for entry in pe.FileInfo:
	            if hasattr(entry, 'StringTable'):
	                for st_entry in entry.StringTable:
	                    for str_entry in st_entry.entries.items():
	                        ret.update({convert_to_printable(str_entry[0]): convert_to_printable(str_entry[1])})
	            elif hasattr(entry, 'Var'):
	                for var_entry in entry.Var:
	                    if hasattr(var_entry, 'entry'):
	                        ret.update({convert_to_printable(var_entry.entry.keys()[0]): convert_to_printable(var_entry.entry.values()[0])})
	
	return ret
