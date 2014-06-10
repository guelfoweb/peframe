#!/usr/bin/env python

# ----------------------------------------------------------------------
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

import os, sys
import time, datetime

sys.path.insert(0, 'modules')

try:
	import pecore
	import json_output
	import std_output
	import db_manage
except ImportError:
	print '[!] Error: library not found in modules folder.'
	sys.exit(0)

# INFORMATION
NAME		= "PEframe"
VERSION		= "4.0"
AUTHOR		= "Author: Gianni 'guelfoweb' Amato"
GITHUB		= "Github: https://github.com/guelfoweb/peframe"
INFO		= NAME+" v."+VERSION+" - Open Source Project\n"+AUTHOR+"\n"+GITHUB

def show_info(filename):
	info = pecore.get_info(filename)
	now  = datetime.datetime.now()
	date = now.strftime("%Y-%m-%d %H:%M")
	name = info[0]
	size = info[1]
	time = datetime.datetime.fromtimestamp(info[2])
	dll  = info[3]
	sect = info[4]
	if dll:
		dll = "Yes"
	else:
		dll = "No"
	return VERSION,str(date),str(name),str(size),str(time),dll,str(sect)

def show_hash(filename):
	hashcode = pecore.get_hash(filename)
	md5      = hashcode[0]
	sha1     = hashcode[1]
	imph     = hashcode[2]
	return md5,sha1,imph

def check_packer(filename):
	peid = pecore.check_peid(filename)
	if peid:
		peid = "Yes"
	else:
		peid = "No"
	return peid

def check_antidbg(filename):
	antidbg = pecore.get_apiantidbg(filename)
	if antidbg:
		antidbg = "Yes"
	else:
		antidbg = "No"
	return antidbg

def check_antivm(filename):
	antivm = pecore.check_antivm(filename)
	if antivm:
		antivm = "Yes"
	else:
		antivm = "No"
	return antivm
	
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

	directory = ", ".join(dirlist)
	return directory

def show_packer(filename):
	peid = pecore.check_peid(filename)
	peid_list = []
	if peid != None:
		len_peid = len(peid)
		for i in range(0, len_peid):
			peid_list.append(peid[i][0])
	return peid_list

def show_antidbg(filename):
	antidbg_list = []
	antidbg      = pecore.get_apiantidbg(filename)
	if antidbg:
		len_antidbg = len(antidbg)
		for i in range(0, len_antidbg):
			antidbg_list.append(antidbg[i])
		return antidbg_list

def show_antivm(filename):
	antivm_list = []
	antivm      = pecore.check_antivm(filename)
	if antivm:
		len_antivm = len(antivm)
		for i in range(0, len_antivm):
			antivm_list.append(antivm[i])
		return antivm_list
	return antivm_list

def show_suspicious(filename):
	apialert_list = []
	apialert      = pecore.get_apialert(filename)
	if apialert:
		len_apialert = len(apialert)
		for i in range(0, len_apialert):
			apialert_list.append(apialert[i])	
		return apialert_list

def show_secsuspicious(filename):
	secsuspicious_list = []
	secsuspicious      = pecore.get_sectionsalert(filename)
	if secsuspicious:
		len_secsuspicious = len(secsuspicious)
		for i in range(0, len_secsuspicious):
			secsuspicious_list.append([secsuspicious[i][0], secsuspicious[i][1], secsuspicious[i][2]])	
		return secsuspicious_list
			
def show_fileurl(filename):
	file_list  = []
	url_list   = []
	getfileurl = pecore.get_fileurl(filename)
	if getfileurl:
		len_url  = len(getfileurl[0])
		len_file = len(getfileurl[1])
		if len_file > 0:
			for i in range(0, len_file):
				file_list.append([getfileurl[1][i][0], getfileurl[1][i][1]])
				
		if len_url > 0:
			for i in range(0, len_url):
				url_list.append(getfileurl[0][i])

		return file_list, url_list
				
def show_meta(filename):
	meta_list = []
	spl       = []
	meta      = pecore.get_meta(filename)
	if meta:
		len_meta = len(meta)
		for i in range(0, len_meta):
			spl.append(meta[i].split(':'))
		for i in range(0, len_meta):
			meta_list.append([str(spl[i][0]), str(spl[i][1])])		
		return meta_list
		
#______________________EXTRA______________________		
				
def show_sections(filename):
	sections      = pecore.get_sections(filename)
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
				suspicious = "Yes"
			else:
				suspicious = "No"
			print 'Suspicious'.ljust(18), suspicious

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
		len_exported = len(exported)
		for i in range(0, len_exported):
			arrayDll.append(exported[i][0])
		print "\nExported [" + str(len_exported) + "] Functions"
		print "-"*60
		for i in range(0, len_exported):
#			dll      = exported[i][0]
			address  = exported[i][1]
			function = exported[i][2]
			print "".ljust(18),address,function	

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

def autoanalysis(filename, json=False, skipdb=False):
	# print results and return values
	# ak = array known, au = array unknown, s = single key
	ak_info  = show_info(filename)
	ak_hash  = show_hash(filename)
	s_pack   = check_packer(filename)
	s_adbg   = check_antidbg(filename)
	s_avm    = check_antivm(filename)
	a_dir    = show_directory(filename) # (*) unknown value

	au_show_pack = show_packer(filename)
	au_show_adbg = show_antidbg(filename)
	au_show_avm  = show_antivm(filename)
	au_show_api  = show_suspicious(filename)
	au_show_sec  = show_secsuspicious(filename)
	au_show_furl = show_fileurl(filename)
	au_show_meta = show_meta(filename)

	# collect SHORT data to store in db	
	pefver  = ak_info[0]
	date    = ak_info[1]
	name    = ak_info[2]
	size    = ak_info[3]
	time    = ak_info[4]
	dll     = ak_info[5]
	sect    = ak_info[6]
	md5     = ak_hash[0]
	sha1    = ak_hash[1]
	imph    = ak_hash[2]
	packer  = s_pack
	antidbg = s_adbg
	antivm  = s_avm
	directory = a_dir # (*) unknown value

	if json:
		# output in json
		json_output.joutput(name,size,time,dll,sect,md5, \
			sha1,imph,packer,antidbg,antivm,directory,pefver,date, \
			au_show_pack,au_show_adbg,au_show_avm,au_show_api, \
			au_show_sec,au_show_furl,au_show_meta)
	else:
		# standard output
		std_output.stdoutput(name,size,time,dll,sect,md5, \
			sha1,imph,packer,antidbg,antivm,directory,pefver,date, \
			au_show_pack,au_show_adbg,au_show_avm,au_show_api, \
			au_show_sec,au_show_furl,au_show_meta)
							
	if not skipdb:
		# manage database
		db_manage.dbmanage(name,size,time,dll,sect,md5, \
				sha1,imph,packer,antidbg,antivm,directory,pefver,date, \
				au_show_pack,au_show_adbg,au_show_avm,au_show_api, \
				au_show_sec,au_show_furl,au_show_meta)
	
#	# other options (to develop)
	
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
	print "".ljust(4), "--skip-db".ljust(14), "Skip database"
	print "".ljust(4), "--json".ljust(14), "Output in json"
	print "".ljust(4), "--json-skip-db".ljust(14), "Output in json and skip database"
	print
	print "".ljust(4), "--import".ljust(14), "Imported DLL and functions"
	print "".ljust(4), "--export".ljust(14), "Exported functions"
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

if len(sys.argv) == 2 and sys.argv[1] == "-h" or sys.argv[1] == "--help":
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

	if option == "--skip-db":
		autoanalysis(filename, json=False, skipdb=True); sys.exit(0)
	if option == "--json":
		autoanalysis(filename, json=True); sys.exit(0)
	if option == "--json-skip-db":
		autoanalysis(filename, json=True, skipdb=True); sys.exit(0)
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

