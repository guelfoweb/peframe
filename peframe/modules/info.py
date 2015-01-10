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

import os
import time, datetime
import hashlib
import json

import directories
import peid
import apiantidbg
import antivm
import xor

import pefile
import peutils

def get_hash(pe, filename):
	# Import Hash 
	# https://www.mandiant.com/blog/tracking-malware-import-hashing/
	ih = pe.get_imphash()

	# Thank to 'Christophe Monniez' for patched hash function
	fh = open(filename, 'rb')
	m = hashlib.md5()
	s = hashlib.sha1()
	
	while True:
		data = fh.read(8192)
		if not data:
			break

		m.update(data)
		s.update(data)

	md5  = m.hexdigest()
	sha1 = s.hexdigest()

	return md5,sha1,ih
	
def get(pe, filename):

	fname = os.path.basename(filename)	# file name -> use (filename)
	fsize = os.path.getsize(filename)	# file size (in byte) -> use (filename)
	
	dll   = pe.FILE_HEADER.IMAGE_FILE_DLL 	# dll -> use (pe)
	nsec  = pe.FILE_HEADER.NumberOfSections	# num sections -> use (pe)

	tstamp = pe.FILE_HEADER.TimeDateStamp	# timestamp -> (pe)
	try:
		""" return date """
		tsdate = datetime.datetime.fromtimestamp(tstamp)
	except:
		""" return timestamp """
		tsdate = str(tstamp) + " [Invalid date]"

	md5, sha1, imphash = get_hash(pe, filename) # get md5, sha1, imphash -> (pe, filename)
	# directory -> (pe)
	dirlist = directories.get(pe)
	
	detected = []

	for sign in dirlist:			# digital signature
		if sign == "Security":
			detected.append("Sign")

	packer = peid.get(pe)			# packer (peid)
	if packer:
		detected.append("Packer")

	antidbg = apiantidbg.get(pe)	# anti debug
	if antidbg:
		detected.append("Anti Debug")

	xorcheck = xor.get(filename) 	# Xor
	if xorcheck[0] and xorcheck[1]:
			detected.append("Xor")

	antivirtualmachine = antivm.get(filename) # anti virtual machine
	if antivirtualmachine:
		detected.append("Anti VM")
	
	return json.dumps({"File Name": fname, \
					"File Size": str(fsize), \
					"Compile Time": str(tsdate), \
					"DLL": dll, \
					"Sections": nsec, \
					"Hash MD5": md5, \
					"Hash SHA-1": sha1, \
					"Import Hash": imphash, \
					"Xor": xorcheck[0], \
					"Detected": detected, \
					"Directories": dirlist
					}, indent=4, separators=(',', ': '))
					
#	return [fname, str(fsize), str(tsdate), dll, nsec, md5, sha1, imphash, dirlist, detected]
