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

import json

import pecore

def show_import(pe):
	import_load = json.loads(pecore.get_import(pe))
	imported = import_load["Imported Functions"]
	
	if imported:
		nfunc = len(imported)

		dlllist = []
		for dll in imported:
			dlllist.append(dll[0])

		ndll = len(set(dlllist))
		
		print "Imported [" + str(ndll) + "] DLL and [" + str(nfunc) + "] Functions"
		print "-"*60
	
		for item in imported:
			print item[0].ljust(18), item[1], item[2]
		
def show_export(pe):
	export_load = json.loads(pecore.get_export(pe))
	exported = export_load["Exported Functions"]
	
	if exported:
		nfunc = len(exported)

		print "Exported [" + str(nfunc) + "] Functions"
		print "-"*60
	
		for item in exported:
			print item[0].ljust(18), item[1]

def show_directory(pe, d):
	print pecore.get_dir(pe, d)

def show_auto(info,cert_dump,peid,antidbg,antivm,xor,apialert,sectionsalert,fileurl,meta):

	#INFO
	info_load = json.loads(info)
	short_info = info_load["Short Info"]
	filename = short_info["File Name"]
	filesize = short_info["File Size"]
	compiletime = short_info["Compile Time"]
	dll = short_info["DLL"]
	sections = short_info["Sections"]
	hashmd5 = short_info["Hash MD5"]
	hashsha1 =  short_info["Hash SHA-1"]
	hashimport = short_info["Import Hash"]
	xorcheck = short_info["Xor"]
	detected = short_info["Detected"]
	directory = short_info["Directories"] # contains a list -> ', '.join(directory)

	print "\nShort information"
	print "-"*60
	print "File Name".ljust(18), str(filename)
	print "File Size".ljust(18), str(filesize), "byte"
	print "Compile Time".ljust(18), str(compiletime)
	print "DLL".ljust(18), str(dll)
	print "Sections".ljust(18), str(sections)
	print "Hash MD5".ljust(18), str(hashmd5)
	print "Hash SHA-1".ljust(18), str(hashsha1)
	if hashimport:
		print "Imphash".ljust(18), str(hashimport)
	if detected:
		print "Detected".ljust(18), ', '.join(detected)
	if directory:
		print "Directory".ljust(18), ', '.join(directory)

	# CERT (Digital Signature)
	if detected:
		for sign in detected:
			if sign == "Sign":
				cert_load = json.loads(cert_dump)
				cert_matched = cert_load["Digital Signature"] # contains a list
				if cert_matched:
					hex_va = hex(cert_matched["Virtual Address"]).split('x')[1]
					print "\nDigital Signature"
					print "-"*60
					print "Virtual Address".ljust(18), str(hex_va).upper()
					print "Block Size".ljust(18), str(cert_matched["Block Size"]) + " byte"
					print "Hash MD5".ljust(18), str(cert_matched["Hash MD5"])
					print "Hash SHA-1".ljust(18), str(cert_matched["Hash SHA-1"])

	# PEID (Packer)
	if detected:
		for packer in detected:
			if packer == "Packer":
				peid_load = json.loads(peid)
				packer_matched = peid_load["Packer"] # contains a list
				if packer_matched:
					print "\nPacker matched ["+str(len(packer_matched))+"]"
					print "-"*60
					for i in range(0, len(packer_matched)):
						print "Packer".ljust(18), packer_matched[i]

	# ANTI DEBUG
		if antidbg:
			antidbg_load = json.loads(antidbg)
			antidbg_matched = antidbg_load["Anti Debug"] # contains a list
			if antidbg_matched:
				print "\nAnti Debug discovered ["+str(len(antidbg_matched))+"]"
				print "-"*60
				for i in range(0, len(antidbg_matched)):
					print "Function".ljust(18), antidbg_matched[i]

	# ANTI VIRTUAL MACHINE
	if antivm:
		antivm_load = json.loads(antivm)
		antivm_matched = antivm_load["Anti VM"]
		if antivm_matched:
			print "\nAnti VM Trick discovered ["+str(len(antivm_matched))+"]"
			print "-"*60
			for i in range(0, len(antivm_matched)):
				print "Trick".ljust(18), antivm_matched[i]

	# XOR
	if "Xor" in detected:
		print "\nXOR discovered"
		print "-"*60
		print "Key length".ljust(18), "Offset (hex)".ljust(18), "Offset (dec)".ljust(18)
		xor_load = json.loads(xor)
		xor = xor_load["Offset"]

		for i in xrange(0, len(xor)):
			print str(xor[i][0]).ljust(18), hex(xor[i][1]).ljust(18), xor[i][1]

	# FUNCTION API ALERT
	if apialert:
		apialert_load = json.loads(apialert)
		apialert_matched = apialert_load["Suspicious API"]
		if apialert_matched:
			print "\nSuspicious API discovered ["+str(len(apialert_matched))+"]"
			print "-"*60
			for i in range(0, len(apialert_matched)):
				print "Function".ljust(18), apialert_matched[i]

	# SECTIONS ALERT
	if sectionsalert:
		sectionsalert_load = json.loads(sectionsalert)
		sectionsalert_matched = sectionsalert_load["Suspicious Sections"]
		if sectionsalert_matched:
			print "\nSuspicious Sections discovered ["+str(len(sectionsalert_matched))+"]"
			print "-"*60
			for item in sectionsalert_matched:
				print "Section".ljust(18), item["Section"]
				print "Hash MD5".ljust(18), item["Hash MD5"]
				print "Hash SHA-1".ljust(18), item["Hash SHA-1"]

	# FILE AND URL FOUND
	if fileurl:
		fileurl_load = json.loads(fileurl)

		# FILE
		file_matched = fileurl_load["File Name"]
		if file_matched:
			file_found = []
			for i in range(0, len(file_matched)):
				for filename in file_matched[i][1]:
					file_found.append([file_matched[i][0], filename])

			print "\nFile name discovered ["+str(len(file_found))+"]" 
			print "-"*60
			for item in file_found:
				print item[0].ljust(18), item[1]
			
			"""
			# Alternative
			
			 count = 0
			 for filename in file_matched[i][1]:
				count = count + 1
				if count == 1:
					print file_matched[i][0].ljust(18), filename
				else:
					print "".ljust(18), filename
			"""

		# URL
		url_matched = fileurl_load["Url"]
		if url_matched:
			print "\nUrl discovered ["+str(len(url_matched))+"]"
			print "-"*60
			for i in range(0, len(url_matched)):
				print "Url".ljust(18), url_matched[i]

	# META FOUND
	if meta:
		meta_load = json.loads(meta)
		meta_matched = meta_load["Meta Data"]
		if meta_matched:
			print "\nMeta data found ["+str(len(meta_matched))+"]"
			print "-"*60
			for i in xrange(0, len(meta_matched)):
				meta_array = meta_matched[i].split(":")
				print meta_array[0].ljust(18), meta_array[1]
