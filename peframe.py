#!/usr/bin/env python

# PEFrame
#
# PEFrame is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Peframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with peframe. If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time, datetime

sys.path.insert(0, 'modules')

try:
	import pecore
except ImportError:
	print '[!] pecore not found.'
	sys.exit(0)

# INFORMATION
NAME		= "PEFrame"
VERSION		= "3.0 rc1"
AUTHOR		= "Author: Gianni 'guelfoweb' Amato"
GITHUB		= "Github: https://github.com/guelfoweb/peframe"
INFO		= NAME+" v."+VERSION+" - Open Source Project\n"+AUTHOR+"\n"+GITHUB

def show_hash(filename):
	hashcode = pecore.get_hash(filename)
	md5      = hashcode[0]
	sha1     = hashcode[1]
	print "Hash MD5".ljust(18), md5
	print "Hash SAH1".ljust(18), sha1

def show_info(filename):
	info = pecore.get_info(filename)
	name = info[0]
	size = info[1]
	time = datetime.datetime.fromtimestamp(info[2])
	dll  = info[3]
	sect = info[4]
	print "File Name".ljust(18), str(name)
	print "File Size".ljust(18), str(size), "byte"
	print "Compile Time".ljust(18), str(time)
	if dll:
		print "DLL".ljust(18), "Yes"
	else:
		print "DLL".ljust(18), "No"
	print "Sections".ljust(18), str(sect)

def check_packer(filename):
	peid = pecore.check_peid(filename)
	if peid:
		print "Packer".ljust(18), "Yes"
	else:
		print "Packer".ljust(18), "No"

def show_packer(filename):
	peid = pecore.check_peid(filename)
	if peid != None:
		len_peid = len(peid)
		print "\nPacker matched [" + str(len_peid) + "]"
		print "-"*60
		for i in range(0, len_peid):
			print "Packer".ljust(18), peid[i][0]

def check_antidbg(filename):
	antidbg = pecore.get_apiantidbg(filename)
	if antidbg:
		print "Anti Debug".ljust(18), "Yes"
		return True
	else:
		print "Anti Debug".ljust(18), "No"
		return False

def show_antidbg(filename):
	antidbg = pecore.get_apiantidbg(filename)
	if antidbg:
		len_antidbg = len(antidbg)
		print "\nAnti Debug discovered [" + str(len_antidbg) + "]"
		print "-"*60
		for i in range(0, len_antidbg):
			print "Anti Debug".ljust(18),antidbg[i]

def check_antivm(filename):
	antivm = pecore.check_antivm(filename)
	if antivm:
		print 'Anti VM'.ljust(18), "Yes"
	else:
		print 'Anti VM'.ljust(18), "No"

def show_antivm(filename):
	antivm = pecore.check_antivm(filename)
	if antivm:
		len_antivm = len(antivm)
		print "\nAnti VM Trick discovered [" + str(len_antivm) + "]"
		print "-"*60
		for i in range(0, len_antivm):
			print 'Trick'.ljust(18), antivm[i]

def show_suspicious(filename):
	apialert = pecore.get_apialert(filename)
	if apialert:
		len_apialert = len(apialert)
		print "\nSuspicious API discovered [" + str(len_apialert) + "]"
		print "-"*60
		for i in range(0, len_apialert):
			print 'Function'.ljust(18), apialert[i]

def show_secsuspicious(filename):
	secsuspicious = pecore.get_sectionsalert(filename)
	if secsuspicious:
		len_secsuspicious = len(secsuspicious)
		print "\nSuspicious Sections discovered [" + str(len_secsuspicious) + "]"
		print "-"*60
		for i in range(0, len_secsuspicious):
			print 'Section'.ljust(18),secsuspicious[i][0]
			print 'Hash MD5'.ljust(18),secsuspicious[i][1]
			print 'Hash SHA-1'.ljust(18),secsuspicious[i][2]
			
def show_fileurl(filename):
	getfileurl = pecore.get_fileurl(filename)
	if getfileurl:
		len_url  = len(getfileurl[0])
		len_file = len(getfileurl[1])
		if len_file > 0:
			print "\nFile name discovered [" + str(len_file) + "]"
			print "-"*60
			for i in range(0, len_file):
				print 'File name'.ljust(18), getfileurl[1][i]
		if len_url > 0:
			print "\nUrl discovered [" + str(len_url) + "]"
			print "-"*60
			for i in range(0, len_url):
				print 'Url'.ljust(18), getfileurl[0][i]
				
def show_meta(filename):
	spl = []
	meta = pecore.get_meta(filename)
	if meta:
		len_meta = len(meta)
		print "\nMeta data found [" + str(len_meta) + "]"
		print "-"*60
		for i in range(0, len_meta):
			spl.append(meta[i].split(':'))
		for i in range(0, len_meta):
			print str(spl[i][0]).ljust(18), str(spl[i][1])
				
def show_sections(filename):
	sections = pecore.get_sections(filename)
	if sections:
		len_sections = len(sections)
		print "\nSections discovered [" + str(len_sections) + "]"
		print "-"*60
		for i in range(0, len_sections):
			print '\nSection'.ljust(18), sections[i][0]
			print 'Hash MD5'.ljust(18), sections[i][1]
			print 'Hash SHA-1'.ljust(18), sections[i][2]		
			print 'VirtualAddress'.ljust(18), sections[i][4]
			print 'VirtualSize'.ljust(18), sections[i][5]
			print 'SizeofRawData'.ljust(18), sections[i][6]
			suspicious = sections[i][3]
			if suspicious:
				print 'Suspicious'.ljust(18), "Yes"
			else:
				print 'Suspicious'.ljust(18), "No"

def show_imported_functions(filename):
	imported = pecore.get_imported_functions(filename)
	arrayDll = []
	if imported:
		len_imported = len(imported)
		for i in range(0, len_imported):
			arrayDll.append(imported[i][0])
		dllfound = set(arrayDll)
		print "\nImported [" + str(len(dllfound)) +"] DLL and [" + str(len_imported) + "] Functions"
		print "-"*60
		for i in range(0, len_imported):
			dll      = imported[i][0]
			address  = imported[i][1]
			function = imported[i][2]
			print dll.ljust(18),address,function

def show_exported_functions(filename):
	exported = pecore.get_exported_functions(filename)
	arrayDll = []
#	print exported
	if exported:
		len_imported = len(exported)
		for i in range(0, len_exported):
			arrayDll.append(exported[i][0])
		dllfound = set(arrayDll)
		print "\nExported [" + str(len(dllfound)) +"] DLL and [" + str(len_exported) + "] Functions"
		print "-"*60
		for i in range(0, len_exported):
			dll      = exported[i][0]
			address  = exported[i][1]
			function = exported[i][2]
			print dll.ljust(18),address,function

def show_directory(filename):
	imports    = pecore.get_import(filename)
	exports    = pecore.get_export(filename)
	resources  = pecore.get_resource(filename)
	debugs     = pecore.get_debug(filename)
	tls        = pecore.get_tls(filename)
	relocation = pecore.get_basereloc(filename)

	dirlist   = []
	
	if imports:
		dirlist.append("Import")
	if exports:
		dirlist.append("Export")
	if resources:
		dirlist.append("Resource")
	if debugs:
		dirlist.append("Debug")
	if tls:
		dirlist.append("TLS")
	if relocation:
		dirlist.append("Relocation")

	print "Directory".ljust(18), ", ".join(dirlist)
			

def show_dump(filename):
	dump = pecore.get_dump(filename)
	print dump

def show_resource_dump(filename, directory):
	if directory == "import":
		imports = pecore.get_import(filename)
		if imports:
			print "\nDirectory dump for " + directory.upper() + " raw data"
			print "-"*60
			print imports
	if directory == "export":
		exports = pecore.get_export(filename)
		print "\nDirectory dump for " + directory.upper() + " raw data"
		print "-"*60
		print exports
	if directory == "resource":
		resources = pecore.get_resource(filename)
		if resources:
			print "\nDirectory dump for " + directory.upper() + " raw data"
			print "-"*60
			print resources
	if directory == "debug":
		debugs = pecore.get_debug(filename)
		if debugs:
			print "\nDirectory dump for " + directory.upper() + " raw data"
			print "-"*60
			print debugs
	if directory == "tls":
		tlss = pecore.get_tls(filename)
		if tlss:
			print "\nDirectory dump for " + directory.upper() + " raw data"
			print "-"*60
			print tlss
	if directory == "relocation":
		relocations = pecore.get_basereloc(filename)
		if relocations:
			print "\nDirectory dump for " + directory.upper() + " raw data"
			print "-"*60
			print relocations

def show_strings(filename):
	strings = pecore.get_strings(filename)
	if(strings):
		for string in strings:
			print string

def check_isfile(filename):
	isfile = os.path.isfile(filename)
	if not isfile:
		print "File not found:", filename
		sys.exit(0)
	ispe = pecore.is_pe(filename)
	if not ispe:
		print "No PE file:", filename
		sys.exit(0)	

def autoanalysis(filename):
	print "\nShort information"
	print "-"*60
	show_info(filename)
	show_hash(filename)
	check_packer(filename)
	check_antidbg(filename)
	check_antivm(filename)
	show_directory(filename)

	show_packer(filename)
	show_antidbg(filename)
	show_antivm(filename)
	show_suspicious(filename)
	show_secsuspicious(filename)
	show_fileurl(filename)
	show_meta(filename)

#	show_sections(filename)
#	show_imported_functions(filename)
#	show_exported_functions(filename)
#	show_dump(filename)
#	show_strings(filename)
#	show_resource_dump(filename, "resource")

def help():
	print INFO
	print
	print "Usage"
	print "".ljust(4), "peframe.py malware.exe"
	print "".ljust(4), "peframe.py [--option] malware.exe"
	print
	print "Option"
	print "".ljust(4), "--import".ljust(14), "Imported function and dll"
	print "".ljust(4), "--export".ljust(14), "Exported function and dll"
	print
	print "".ljust(4), "--dir-import".ljust(14), "Import directory"
	print "".ljust(4), "--dir-export".ljust(14), "Export directory"
	print "".ljust(4), "--dir-resource".ljust(14), "Resource directory"
	print "".ljust(4), "--dir-debug".ljust(14), "Debug directory"
	print "".ljust(4), "--dir-tls".ljust(14), "TLS directory"
	print "".ljust(4), "--dir-reloc".ljust(14), "Relocation directory"
	print
	print "".ljust(4), "--strings".ljust(14), "Get all strings"
	print "".ljust(4), "--sections".ljust(14), "Sections information"
	print "".ljust(4), "--dump".ljust(14), "Dump all information"

	sys.exit(0)

#______________________MAIN______________________

# Help
if len(sys.argv) == 1 or len(sys.argv) > 3:
	help()

# Auto Analysis
if len(sys.argv) == 2:
	filename = sys.argv[1]
	check_isfile(filename)
	autoanalysis(filename)

# Options
if len(sys.argv) == 3:
	option   = sys.argv[1]
	filename = sys.argv[2]
	check_isfile(filename)

	if option == "--info":
		show_info(filename); sys.exit(0)
	elif option == "--hash":
		show_hash(filename); sys.exit(0)
	elif option == "--peid":
		show_packer(filename); sys.exit(0)		
	elif option == "--antidbg":
		show_antidbg(filename); sys.exit(0)
	elif option == "--antivm":
		show_antivm(filename); sys.exit(0)
	elif option == "--suspicious":
		show_suspicious(filename); sys.exit(0)
	elif option == "--secsuspicious":
		show_secsuspicious(filename); sys.exit(0)
	elif option == "--fileurl":
		show_fileurl(filename); sys.exit(0)
	elif option == "--meta":
		show_meta(filename); sys.exit(0)
	elif option == "--import":
		show_imported_functions(filename); sys.exit(0)
	elif option == "--export":
		show_exported_functions(filename); sys.exit(0)
	elif option == "--dir-import":
		show_resource_dump(filename, "import"); sys.exit(0)
	elif option == "--dir-export":
		show_resource_dump(filename, "export"); sys.exit(0)
	elif option == "--dir-resource":
		show_resource_dump(filename, "resource"); sys.exit(0)
	elif option == "--dir-debug":
		show_resource_dump(filename, "debug"); sys.exit(0)
	elif option == "--dir-tls":
		show_resource_dump(filename, "tls"); sys.exit(0)
	elif option == "--dir-reloc":
		show_resource_dump(filename, "relocation"); sys.exit(0)
	elif option == "--strings":
		show_strings(filename); sys.exit(0)
	elif option == "--sections":
		show_sections(filename); sys.exit(0)
	elif option == "--dump":
		show_dump(filename); sys.exit(0)
	else:
		help()


