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

import pefile
import peutils

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


