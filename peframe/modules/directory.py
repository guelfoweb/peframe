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

def get_import(pe):
	try:
		imports = pe.DIRECTORY_ENTRY_IMPORT[0].struct
	except:
		try:
			imports = pe.DIRECTORY_ENTRY_IMPORT.struct
		except:
			try:
				imports = pe.DIRECTORY_ENTRY_IMPORT
			except:
				return False
	
	return imports

def get_export(pe):
	try:
		exports = pe.DIRECTORY_ENTRY_EXPORT[0].struct
	except:
		try:
			exports = pe.DIRECTORY_ENTRY_EXPORT.struct
		except:
			try:
				exports = pe.DIRECTORY_ENTRY_EXPORT
			except:
				return False

	return exports

def get_resource(pe):
	try:
		resources = pe.DIRECTORY_ENTRY_RESOURCE[0].struct
	except:
		try:
			resources = pe.DIRECTORY_ENTRY_RESOURCE.struct
		except:
			try:
				resources = pe.DIRECTORY_ENTRY_RESOURCE
			except:
				return False

	return resources

def get_debug(pe):
	try:
		debug = pe.DIRECTORY_ENTRY_DEBUG[0].struct
	except:
		try:
			debug = pe.DIRECTORY_ENTRY_DEBUG.struct
		except:
			try:
				debug = pe.DIRECTORY_ENTRY_DEBUG
			except:
				return False

	return debug

def get_tls(pe):
	try:
		tls = pefile.DIRECTORY_ENTRY_TLS[0].struct
	except:
		try:
			tls = pe.DIRECTORY_ENTRY_TLS.struct
		except:
			try:
				tls = pe.DIRECTORY_ENTRY_TLS
			except:
				return False

	return tls

def get_basereloc(pe):
	try:
		basereloc = pefile.DIRECTORY_ENTRY_BASERELOC[0].struct
	except:
		try:
			basereloc = pe.DIRECTORY_ENTRY_BASERELOC.struct
		except:
			try:
				basereloc = pe.DIRECTORY_ENTRY_BASERELOC
			except:
				return False

	return basereloc


