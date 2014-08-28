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

import hashlib
import json

try:
	import pefile
	import peutils
except ImportError:
	print 'Error: import pefile or peutils modules failed.'
	sys.exit(0)

def get(pe):

	# Virtual Address
	cert_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

	# Size
	cert_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

	if cert_address != 0 and cert_size !=0:
		signature = pe.write()[cert_address+8:]
		cert_md5  = hashlib.md5(signature).hexdigest()
		cert_sha1 = hashlib.sha1(signature).hexdigest()
		signed = True
	else:
		cert_md5  = False
		cert_sha1 = False
		signed = False

	return json.dumps({"Virtual Address": cert_address, \
					"Block Size": cert_size, \
					"Hash MD5": cert_md5, \
					"Hash SHA-1": cert_sha1
					}, indent=4, separators=(',', ': '))

#	return signed, cert_address, cert_size, cert_md5, cert_sha1

