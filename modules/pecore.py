#!/usr/bin/env python

# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
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
import sys
import string
import os
import math
import time
import subprocess
import hashlib

#sys.path.append(pathname + os.sep + 'modules')

try:
	import pefile
	import peutils
except ImportError:
	print '[!] import pefile module failed.'
	sys.exit(0)

def is_pe(filename):
	try:
		pe = pefile.PE(filename)
		return True
	except:
		return False

# Print HASH MD5 & SHA1
def get_hash(filename):
	pe = pefile.PE(filename)
	ih = pe.get_imphash()

	# Thank to Christophe Monniez for patched hash function
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
	return md5, sha1, ih

# Print PE file attributes
def get_info(filename):
	pe = pefile.PE(filename)
	fn = os.path.basename(filename) 		# file name
	fs = os.path.getsize(filename)			# file size (in byte)
	ts = pe.FILE_HEADER.TimeDateStamp 		# timestamp
	dl = pe.FILE_HEADER.IMAGE_FILE_DLL		# dll
	sc = pe.FILE_HEADER.NumberOfSections	# sections

	#print "Optional Header:\t\t", hex(pe.OPTIONAL_HEADER.ImageBase)
	#print "Address Of Entry Point:\t\t", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	#print "Subsystem:\t\t\t", pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem]
	#machine = 0
	#machine = pe.FILE_HEADER.Machine
	#print "Required CPU type:\t\t", pefile.MACHINE_TYPE[machine]
	#print "Number of RVA and Sizes:\t", pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

	return fn, fs, ts, dl, sc

# Check for version info & metadata
def convert_char(char):
    if char in string.ascii_letters or \
       char in string.digits or \
       char in string.punctuation or \
       char in string.whitespace:
        return char
    else:
        return r'\x%02x' % ord(char)

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])
            
def get_meta(filename):
	pe  = pefile.PE(filename)
	ret = []	
	if hasattr(pe, 'VS_VERSIONINFO'):
	    if hasattr(pe, 'FileInfo'):
	        for entry in pe.FileInfo:
	            if hasattr(entry, 'StringTable'):
	                for st_entry in entry.StringTable:
	                    for str_entry in st_entry.entries.items():
	                        ret.append(convert_to_printable(str_entry[0])+': '+convert_to_printable(str_entry[1]))
	            elif hasattr(entry, 'Var'):
	                for var_entry in entry.Var:
	                    if hasattr(var_entry, 'entry'):
	                        ret.append(convert_to_printable(var_entry.entry.keys()[0]) + ': ' + convert_to_printable(var_entry.entry.values()[0]))
#	prntbl = '\n'.join(ret)
	return ret

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

def get_strings(filename):
	array = []
	PEtoStr = open(filename, 'rb')
	for string in get_process(PEtoStr):
		array.append(string)
	PEtoStr.close()
	return array

# Section analyzer
def get_sections(filename):
	pe    = pefile.PE(filename)
	array = []
	for section in pe.sections:
		section.get_entropy()
		if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
			suspicious = True
		else:
			suspicious = False
		
		scn  = section.Name
		md5  = section.get_hash_md5()
		sha1 = section.get_hash_sha1()
		spc  = suspicious
		va   = hex(section.VirtualAddress)
		vs   = hex(section.Misc_VirtualSize)
		srd  = section.SizeOfRawData

		array.append([scn, md5, sha1, spc, va, vs, srd])

	if array:
		return array
	else:
		return False

# Load PEID userdb.txt database and scan file
pathname = os.path.abspath('modules' + os.sep + 'userdb.txt') #	return pathname
def check_peid(filename):
    signatures = peutils.SignatureDatabase(pathname)
    pe         = pefile.PE(filename)
    matches    = signatures.match_all(pe,ep_only = True)
    return matches

# Check for Anti VM
def check_antivm(filename):
	# Credit: Joxean Koret
	trk     = []
	VM_Str  = {
		"Virtual Box":"VBox",
		"VMware":"WMvare"
	}
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

	if trk:
		return trk
	else:
		return False

# Check url and file name
def get_fileurl(filename):
	PEtoStr        = open(filename, 'rb')
	array          = [] # word raw
	arrayURL       = [] # url
	arrayFILE      = [] # file raw
	arrayFileNames = [] # description and file name

	for found_str in get_process(PEtoStr):
		fname = re.findall("(.+\.([a-z]{2,3}$))+", found_str, re.IGNORECASE | re.MULTILINE)
		if fname:
			word = fname[0][0]
			array.append(word)
			
	for elem in sorted(set(array)):
		match = re.search("^http:|^ftp:|^sftp:|^ssh:|^www|.com$|.org$|.it$|.co.uk$|.ru$|.jp$|.net$|.ly$|.gl$|^([0-9]{1,3})(?:\.[0-9]{1,3}){3}$", elem, re.IGNORECASE)
		if match and len(elem) > 6: # len(c.it) = 4 <- flase positive
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

	return arrayURL, arrayFileNames
	PEtoStr.close()

# Directory
def get_import(filename):
	pe = pefile.PE(filename)
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

def get_export(filename):
	pe = pefile.PE(filename)
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

def get_resource(filename):
	pe = pefile.PE(filename)
#	print [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
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

def get_debug(filename):
	pe = pefile.PE(filename)
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

def get_tls(filename):
	pe = pefile.PE(filename)
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

def get_basereloc(filename):
	pe = pefile.PE(filename)
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


# Imports DLL and API Functions
def get_imported_functions(filename):
	pe    = pefile.PE(filename)
	array = []
	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll = entry.dll
			for imp in entry.imports:
				address = hex(imp.address)
				function = imp.name
				array.append([dll, address, function])		
		return array
	except:
		return False

# Exports DLL and API Functions
def get_exported_functions(filename):
	pe    = pefile.PE(filename)
	array = []
	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
#			print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
			dll = exp.dll
			for imp in exp.expports:
				address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
				function = exp.name
				array.append([dll, address, function])		
		return array
	except:
		return False

def loadfile(filename):
	try:
		filename = open(filename,'r')
		wlist = filename.read().split('\n')
		filename.close
		return wlist
	except:
		return False

def load_api_list(filename):
	wlist = loadfile(filename)
	if wlist == False:
		print "File not found ["+filename+"]"
		sys.exit(0)
	return wlist

# Load array by file alerts.txt - Suspicious Functions API and Sections
filename = os.path.abspath('modules' + os.sep + 'alerts.txt') #	return pathname
alerts   = load_api_list(filename)

# Load array by file antidbg.txt - Suspicious Functions Anti Debug
filename = os.path.abspath('modules' + os.sep + 'antidbg.txt') # return pathname
antidbgs = load_api_list(filename)

# Suspicious Functions Anti Debug
def get_apiantidbg(filename):
	pe    = pefile.PE(filename)
	array = []
	DEI   = hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
	if DEI:
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in lib.imports:
				for antidbg in antidbgs:
					if antidbg:
						if str(imp.name).startswith(antidbg):
							array.append(imp.name)
	if array:
		return sorted(set(array))
	else:
		return False

# Suspicious Functions Api Import
def get_apialert(filename):
	pe    = pefile.PE(filename)
	array = []
	DEI   = hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
	if DEI:
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in lib.imports:
				for alert in alerts:
					if alert:
						if str(imp.name).startswith(alert):
							array.append(imp.name)
	if array:
		return sorted(set(array))
	else:
		return False

# Entropy
def get_sectionsalert(filename):
	pe    = pefile.PE(filename)
	array = []
	for section in pe.sections:
		section.get_entropy()
		if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
			sc   = section.Name
			md5  = section.get_hash_md5()
			sha1 = section.get_hash_sha1()
			array.append([sc, md5, sha1])
	if array:
		return array
	else:
		return False

def get_suspicious():
	print "Suspicious API Functions:"
	get_apialert()
	print "\nSuspicious API Anti-Debug:"
	get_apiantidbg(1)
	print "\nSuspicious Sections:"
	get_sectionsalert()

# Dumping all the information
def get_dump(filename):
	pe = pefile.PE(filename)
	return pe.dump_info()

