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

try:
	import pefile
	import peutils
except ImportError:
	print 'Error: import pefile or peutils modules failed.'
	exit(0)

def get(pe):
	
	# The directory of imported symbols
	dir_import = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
	# The directory of exported symbols; mostly used for DLLs.
	dir_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
	# Debug directory - contents is compiler dependent.
	dir_debug = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress
	# Thread local storage directory - structure unknown; contains variables that are declared
	dir_tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].VirtualAddress
	# The resources, such as dialog boxes, menus, icons and so on, are stored in the data directory
	dir_resource = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
	# PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
	dir_relocation = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].VirtualAddress
	# PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
	dir_security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
	
	dirlist   = []
	
	if dir_import:
		dirlist.append("Import")
	if dir_export:
		dirlist.append("Export")
	if dir_resource:
		dirlist.append("Resource")
	if dir_debug:
		dirlist.append("Debug")
	if dir_tls:
		dirlist.append("TLS")
	if dir_relocation:
		dirlist.append("Relocation")
	if dir_security:
		dirlist.append("Security")
			
	return dirlist	
