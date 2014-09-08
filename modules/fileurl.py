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

import re
import string

# Extract Strings
printable = set(string.printable)
def get_process(stream):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        if not data:
            break
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                yield found_str
                found_str = ""
            else:
                found_str = ""

def get(filename):
	PEtoStr        = open(filename, 'rb')
	array          = [] # word raw
	arrayURL       = [] # url
	arrayFILE      = [] # file raw
	arrayFileNames = [] # description, filename

	for found_str in get_process(PEtoStr):
		fname = re.findall("(.+\.([a-z]{2,3}$))+", found_str, re.IGNORECASE | re.MULTILINE)
		if fname:
			word = fname[0][0]
			array.append(word)
			
	for elem in sorted(set(array)):
		match = re.search("^http:|^ftp:|^sftp:|^ssh:|^www|.com$|.org$|.it$|.co.uk$|.ru$|.jp$|.net$|.ly$|.gl$|^([0-9]{1,3})(?:\.[0-9]{1,3}){3}$", elem, re.IGNORECASE)
		if match and len(elem) > 6: # len(c.it) = 4 <- false positive
			arrayURL.append(elem)
		else:
			arrayFILE.append(elem)

	for elem in sorted(set(arrayFILE)):
		file_type = {
			"Video":".3gp",
			"Compressed":".7z",
			"Video":".asf",
			"Web Page":".asp",
			"Web Page":".aspx",
			"Video":".asx",
			"Video":".avi",
			"Backup":".bak",
			"Binary":".bin",
			"Image":".bmp",
			"Cabinet":".cab",
			"Data":".dat",
			"Database":".db",
			"Word":".doc",
			"Word":".docx",
			"Library":".dll",
			"Autocad":".dwg",
			"Executable":".exe",
			"Email":".eml",
			"Video":".flv",
			"FTP Config":".ftp",
			"Image":".gif",
			"Compressed":".gz",
			"Web Page":".htm",
			"Web Page":".html",
			"Disc Image":".iso",
			"Log":".log",
			"Archive Java":".jar",
			"Image":".jpg",
			"Image":".jepg",
			"Audio":".mp3",
			"Video":".mp4",
			"Video":".mpg",
			"Video":".mpeg",
			"Video":".mov",
			"Installer":".msi",
			"Object":".oca",
			"Object":".ocx",
			"Autogen":".olb",
			"Backup":".old",
			"Registry":".reg",
			"Portable":".pdf",
			"Web Page":".php",
			"Image":".png",
			"Slideshow":".pps",
			"Presentation":".ppt",
			"Image":".psd",
			"Email":".pst",
			"Document":".pub",
			"Compressed":".rar",
			"Text":".rtf",
			"Query DB":".sql",
			"Adobe Flash":".swf",
			"Image":".tif",
			"Temporary":".tmp",
			"Text":".txt",
			"Compressed":".tgz",
			"Audio":".wav",
			"Audio":".wma",
			"Video":".wmv",
			"Excel":".xls",
			"Excel":".xlsx",
			"Compressed":".zip"
		}

		for descr in file_type:
			match = re.search(file_type[descr]+"$", elem, re.IGNORECASE)
			if match:
				arrayFileNames.append([descr, elem])

	filelist = []
	
	if arrayFileNames:
		"""
		arrayFileNames ->

		[ ['Web Page', 'gate.php'], 
		['Binary',   'core_x86.bin'], 
		['Binary',   'dropper_x86.bin'], 
		['Library',  'IPHLPAPI.DLL'],
		['Library',  'WININET.dll'] ]
		"""
		# Get unique tuple from list
		uniq_descr = []
		[item for item in arrayFileNames if item[0] not in uniq_descr and not uniq_descr.append(item[0])]

		# uniq_descr -> ['Web Page', 'Library', 'Binary']
		
		found = {}
		match = []
		
		for descr in uniq_descr:
			for elem in arrayFileNames:
				if elem[0] == descr:
					match.append(elem[1])
			found[descr] = match
			match = []
			
		filelist = found.items()

		"""
		'print found' -> Dictionary {}

		{ 'Binary': ['core_x86.bin', 'dropper_x86.bin'], 
		'Web Page': ['gate.php'], 
		'Library': ['IPHLPAPI.DLL', 'WININET.dll'] }


		'print found.items()' -> List []

		[ ('Binary',   ['core_x86.bin', 'dropper_x86.bin']), 
		('Web Page', ['gate.php']),
		('Library',  ['IPHLPAPI.DLL', 'WININET.dll']) ]
		"""

	return filelist, arrayURL
