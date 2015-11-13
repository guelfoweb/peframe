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
import string

res_array = []
def get(pe):
	try:
		for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
			if resource_type.name is not None:
				name = "%s" % resource_type.name
			else:
				name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)

			if name == None:
				name = "%d" % resource_type.struct.Id

			if hasattr(resource_type, 'directory'):
				for resource_id in resource_type.directory.entries:
					if hasattr(resource_id, 'directory'):
						for resource_lang in resource_id.directory.entries:
							try:
								data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
							except:
								pass
							lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
							sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )

							data = filter(lambda x: x in string.printable, data)

			#print name, data, lang, sublang, hex(resource_lang.data.struct.OffsetToData), resource_lang.data.struct.Size
			res_array.append({"name": name, "data": data, "offset": hex(resource_lang.data.struct.OffsetToData), "size": resource_lang.data.struct.Size, "language": lang, "sublanguage": sublang})
	except:
		pass

	return res_array

'''
# resource types					# description
RT_CURSOR = 1						# Hardware-dependent cursor resource.
RT_BITMAP = 2						# Bitmap resource.
RT_ICON = 3							# Hardware-dependent icon resource.
RT_MENU = 4							# Menu resource.
RT_DIALOG = 5						# Dialog box.
RT_STRING = 6						# String-table entry.
RT_FONTDIR = 7						# Font directory resource.
RT_FONT = 8							# Font resource.
RT_ACCELERATOR = 9					# Accelerator table.
RT_RCDATA = 10						# Application-defined resource (raw data.)
RT_MESSAGETABLE = 11				# Message-table entry.
RT_VERSION = 16						# Version resource.
RT_DLGINCLUDE = 17					# Allows a resource editing tool to associate a string with an .rc file.
RT_PLUGPLAY = 19					# Plug and Play resource.
RT_VXD = 20							# VXD.
RT_ANICURSOR = 21					# Animated cursor.
RT_ANIICON = 22						# Animated icon.
RT_HTML = 23						# HTML resource.
RT_MANIFEST = 24					# Side-by-Side Assembly Manifest.

RT_GROUP_CURSOR = RT_CURSOR + 11	# Hardware-independent cursor resource.
RT_GROUP_ICON = RT_ICON + 11		# Hardware-independent icon resource.
'''
