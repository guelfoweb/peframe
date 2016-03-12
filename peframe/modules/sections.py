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

import pefile

def get(pe):
	array = []
	for section in pe.sections:
		entropy = section.get_entropy()

		reasons = []
		suspicious = False
		if section.SizeOfRawData == 0:
			suspicious = True
			reasons.append("Size of Raw data is 0.")
		if (entropy > 0 and entropy < 1):
			suspicious = True
			reasons.append("Small entropy: %f of 8." % entropy)
		elif entropy > 7:
			suspicious = True
			reasons.append("Large entropy: %f of 8." % entropy)

		scn  = section.Name
		scn  = unicode(scn, errors='replace')
		md5  = section.get_hash_md5()
		sha1 = section.get_hash_sha1()
		spc  = suspicious
		va   = hex(section.VirtualAddress)
		vs   = hex(section.Misc_VirtualSize)
		srd  = section.SizeOfRawData

		array.append({"name": scn, "hash_md5": md5, "hash_sha1": sha1, "suspicious": spc, "virtual_address": va, "virtual_size": vs, "size_raw_data": srd, "reasons": '\n'.join(reasons)})

	return array
