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

import array
import binascii
 
def xor_delta(s, key_len = 1):
    delta = array.array('B', s)
     
    for x in xrange(key_len, len(s)):
        delta[x - key_len] ^= delta[x]
         
    """ return the delta as a string """
    return delta.tostring()[:-key_len]
 
def get(filename):
	check = {}
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
				check.update({l: offset})
			else:
				break

	detect = [item for item in check.items() if item[1] == 78]

	if detect or check == {}:
		return {}
	else:
		return check
