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

import re

def get(filename):
	
	trk     = []
	
	VM_Str  = {
		"Virtual Box":"VBox",
		"VMware":"WMvare"
	}
	
	# Credit: Joxean Koret
	VM_Sign = {
		"Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
		"VirtualPc trick":"\x0f\x3f\x07\x0b",
		"VMware trick":"VMXh",
		"VMCheck.dll":"\x45\xC7\x00\x01",
		"VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
		"Xen":"XenVMM",
		"Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
		"Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
		"Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
		}
		
	with open(filename, "rb") as f:
		buf = f.read()
		for string in VM_Str:
			match = re.findall(VM_Str[string], buf, re.IGNORECASE | re.MULTILINE)
			if match:
				trk.append(string)
				
		for trick in VM_Sign:
			if buf.find(VM_Sign[trick][::-1]) > -1:
				trk.append(trick)

	return trk
