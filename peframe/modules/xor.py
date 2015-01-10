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

import array
import binascii
 
def xor_delta(s, key_len = 1):
    delta = array.array('B', s)
     
    for x in xrange(key_len, len(s)):
        delta[x - key_len] ^= delta[x]
         
    """ return the delta as a string """
    return delta.tostring()[:-key_len]
 
def get(filename):
	check = []
	search_file = open(filename, "r").read()
	key_lengths=[1,2,4,8]
	search_string = "This program cannot be run in DOS mode."
	 
	for l in key_lengths:
		key_delta = xor_delta(search_string, l)
		 
		doc_delta = xor_delta(search_file, l)
		 
		offset = -1
		while(True):
			offset += 1
			offset = doc_delta.find(key_delta, offset)
			if(offset > 0):
				check.append((l, offset))
			else:
				break

	detect = [item for item in check if item[1] == 78]

	if detect:
		return False, check
	else:
		return True, check
