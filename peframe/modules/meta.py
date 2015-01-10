#!/usr/bin/env python

# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

import string

import pefile
import peutils


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
	ret = []	
	if hasattr(pe, 'VS_VERSIONINFO'):
	    if hasattr(pe, 'FileInfo'):
	        for entry in pe.FileInfo:
	            if hasattr(entry, 'StringTable'):
	                for st_entry in entry.StringTable:
	                    for str_entry in st_entry.entries.items():
	                        ret.append(convert_to_printable(str_entry[0])+': '+convert_to_printable(str_entry[1]))
	            elif hasattr(entry, 'Var'):
	                for var_entry in entry.Var:
	                    if hasattr(var_entry, 'entry'):
	                        ret.append(convert_to_printable(var_entry.entry.keys()[0]) + ': ' + convert_to_printable(var_entry.entry.values()[0]))
	
	return ret
